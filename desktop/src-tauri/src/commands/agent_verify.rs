//! Agent-to-agent identity verification against the ZipViz registry.
//!
//! A verifier agent posts a request naming a prover agent, both `.viz` names
//! and a fresh nonce. The prover agent answers in the request's thread with a
//! kind:30388 event signed by its own Nostr key that binds both names and the
//! nonce. Any viewer can then check the answer: first locally (id, signature,
//! signer, binding to the request, freshness), then with the registry
//! (`POST /v1/verify`), which confirms that the signing key is the live linked
//! key of the prover's `.viz` name.
//!
//! Key custody: the proof event is built here from validated request fields in
//! one fixed format, never from caller-supplied bytes, and is signed only with
//! the managed agent the request names. Keys never leave this process. The
//! proof format is deliberately distinct from registry link/revoke consent
//! statements, so a proof can never be replayed as consent.
//!
//! Both messages are read back from the relay before use; the webview only
//! passes event ids, so it cannot substitute request or proof content.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::{
    app_state::AppState,
    managed_agents::{find_managed_agent_mut, load_managed_agents},
    models::SendChannelMessageResponse,
    relay::query_relay,
};

use super::send_managed_agent_channel_message;

/// First line of a verification request message.
pub(crate) const REQUEST_MARKER: &str = "<!-- zipviz:agent-verify-request:v1 -->";
/// First line of a verification proof message.
pub(crate) const PROOF_MARKER: &str = "<!-- zipviz:agent-verify-proof:v1 -->";
/// The only event kind the registry accepts for online Nostr verification.
pub(crate) const PROOF_KIND: u16 = 30388;
/// Version label carried in the proof content and `v` tag.
pub(crate) const PROOF_VERSION: &str = "zipviz:agent-verify:v1";
/// Registry endpoint for online verification.
const REGISTRY_VERIFY_URL: &str = "https://api.zipviz.ai/v1/verify";
/// Same ±5 minute window the registry applies to event `created_at`.
pub(crate) const FRESHNESS_SECS: u64 = 300;
/// Upper bound on a proof event's serialized size (registry limit is 16 KiB
/// for the whole request body).
const MAX_PROOF_EVENT_BYTES: usize = 8192;
/// Upper bound on a registry response body we are willing to parse.
const MAX_REGISTRY_RESPONSE_BYTES: usize = 64 * 1024;
/// Message kinds a request or proof can arrive in.
const MESSAGE_KINDS: [u32; 2] = [9, 40002];

/// A verification request as carried in the request message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyRequest {
    pub verifier: String,
    pub verifier_pubkey: String,
    pub prover: String,
    pub prover_pubkey: String,
    pub nonce: String,
}

/// Result of checking a proof, as shown in the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// The registry confirmed the proof's key is the prover's live linked key.
    Verified {
        identity: String,
        verifier: String,
        nostr_pubkey: String,
        event_id: String,
        proof_id: Option<String>,
        /// The registry's current link incarnation (lowercase hex32), when
        /// reported in that exact form.
        incarnation: Option<String>,
        checked_at: u64,
        /// The registry's behavior reading for this identity, verbatim.
        /// `None` when the registry reported none or an unexpected shape.
        reputation: Option<Reputation>,
        /// The registry's trust status. `None` when not reported.
        blue_tick: Option<bool>,
    },
    /// The proof is invalid, does not answer this request, or the registry
    /// refused it.
    Rejected { code: String },
    /// The registry could not give an answer (not configured, overloaded or
    /// unreachable). Not a verification.
    Unavailable { code: String },
}

/// Behavior reading as the registry reports it (frozen `/v1/verify` shape).
/// Displayed as reported; nothing here is computed or inferred locally.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reputation {
    pub entropy_score: Option<f64>,
    pub drift_detected: Option<bool>,
    pub z_score: Option<f64>,
    pub calibration_stage: Option<String>,
}

impl Eq for Reputation {}

const CALIBRATION_STAGES: [&str; 8] = [
    "unseen",
    "uncalibrated",
    "declared",
    "cohort",
    "basic",
    "full",
    "degenerate",
    "calibrated",
];

/// Strictly read the registry's `reputation` object; any unexpected shape
/// yields `None` so the app shows the reading as unavailable.
fn parse_reputation(value: Option<&serde_json::Value>) -> Option<Reputation> {
    let object = value?.as_object()?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "entropy_score" | "drift_detected" | "z_score" | "calibration_stage"
        )
    }) {
        return None;
    }
    fn number(value: Option<&serde_json::Value>) -> Result<Option<f64>, ()> {
        match value {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Number(n)) => {
                n.as_f64().filter(|f| f.is_finite()).map(Some).ok_or(())
            }
            _ => Err(()),
        }
    }
    let drift_detected = match object.get("drift_detected") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(b)) => Some(*b),
        _ => return None,
    };
    let calibration_stage = match object.get("calibration_stage") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(stage)) if CALIBRATION_STAGES.contains(&stage.as_str()) => {
            Some(stage.clone())
        }
        _ => return None,
    };
    Some(Reputation {
        entropy_score: number(object.get("entropy_score")).ok()?,
        drift_detected,
        z_score: number(object.get("z_score")).ok()?,
        calibration_stage,
    })
}

fn rejected(code: &str) -> VerifyOutcome {
    VerifyOutcome::Rejected {
        code: code.to_string(),
    }
}

fn unavailable(code: &str) -> VerifyOutcome {
    VerifyOutcome::Unavailable {
        code: code.to_string(),
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Agent `.viz` name, same shape the registry accepts.
pub(crate) fn is_viz_domain(value: &str) -> bool {
    fn label(part: &str) -> bool {
        let bytes = part.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 20
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    }
    let Some(stem) = value.strip_suffix(".viz") else {
        return false;
    };
    let parts: Vec<&str> = stem.split('.').collect();
    (parts.len() == 1 || parts.len() == 2) && parts.iter().all(|part| label(part))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl VerifyRequest {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !is_viz_domain(&self.verifier) || !is_viz_domain(&self.prover) {
            return Err("names must be agent .viz names".into());
        }
        if !is_lower_hex(&self.verifier_pubkey, 64) || !is_lower_hex(&self.prover_pubkey, 64) {
            return Err("public keys must be lowercase hex".into());
        }
        if !is_lower_hex(&self.nonce, 32) {
            return Err("nonce must be 16 bytes of lowercase hex".into());
        }
        if self.verifier_pubkey == self.prover_pubkey || self.verifier == self.prover {
            return Err("an agent cannot verify itself".into());
        }
        Ok(())
    }
}

// ── Message formats ─────────────────────────────────────────────────────────

pub(crate) fn format_request(request: &VerifyRequest) -> Result<String, String> {
    request.validate()?;
    let json = serde_json::to_string(request).map_err(|e| format!("encode request: {e}"))?;
    Ok(format!(
        "{REQUEST_MARKER}\n{json}\n{} asked {} to verify its identity.",
        request.verifier, request.prover
    ))
}

/// The JSON line that follows `marker`, if `content` starts with it.
fn marked_payload<'a>(content: &'a str, marker: &str) -> Option<&'a str> {
    let rest = content.trim_start().strip_prefix(marker)?;
    rest.lines().map(str::trim).find(|line| !line.is_empty())
}

pub(crate) fn parse_request(content: &str) -> Result<VerifyRequest, String> {
    let payload = marked_payload(content, REQUEST_MARKER).ok_or("not a verification request")?;
    let request: VerifyRequest =
        serde_json::from_str(payload).map_err(|_| "malformed verification request")?;
    request.validate()?;
    Ok(request)
}

pub(crate) fn proof_content(request: &VerifyRequest) -> String {
    format!(
        "{PROOF_VERSION}:{}:{}:{}",
        request.prover, request.verifier, request.nonce
    )
}

pub(crate) fn proof_tags(request: &VerifyRequest) -> Vec<Vec<String>> {
    vec![
        vec!["d".into(), format!("zipviz-verify:{}", request.nonce)],
        vec!["p".into(), request.verifier_pubkey.clone()],
        vec!["v".into(), PROOF_VERSION.into()],
    ]
}

/// Build and sign the proof for `request` with the prover's own keys.
pub(crate) fn build_proof_event(
    keys: &Keys,
    request: &VerifyRequest,
    created_at: u64,
) -> Result<Event, String> {
    request.validate()?;
    if keys.public_key().to_hex() != request.prover_pubkey {
        return Err("signing key is not the requested prover".into());
    }
    let tags = proof_tags(request)
        .into_iter()
        .map(|tag| Tag::parse(tag).map_err(|e| format!("invalid tag: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    EventBuilder::new(Kind::Custom(PROOF_KIND), proof_content(request))
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .map_err(|e| format!("sign failed: {e}"))
}

pub(crate) fn format_proof(event: &Event) -> String {
    format!("{PROOF_MARKER}\n{}", event.as_json())
}

pub(crate) fn parse_proof(content: &str) -> Result<Event, String> {
    let payload = marked_payload(content, PROOF_MARKER).ok_or("not a verification proof")?;
    if payload.len() > MAX_PROOF_EVENT_BYTES {
        return Err("proof too large".into());
    }
    Event::from_json(payload).map_err(|_| "malformed proof".into())
}

// ── Checks ──────────────────────────────────────────────────────────────────

/// Local checks: the proof is intact, signed by the requested prover, answers
/// exactly this request and is fresh. Returns the rejection code on failure.
pub(crate) fn check_binding(
    event: &Event,
    request: &VerifyRequest,
    now_secs: u64,
) -> Result<(), &'static str> {
    if !event.verify_id() {
        return Err("E_PROOF_ID_MISMATCH");
    }
    if !event.verify_signature() {
        return Err("E_PROOF_SIG_INVALID");
    }
    if event.kind != Kind::Custom(PROOF_KIND) {
        return Err("E_PROOF_KIND");
    }
    if event.pubkey.to_hex() != request.prover_pubkey {
        return Err("E_PROOF_WRONG_SIGNER");
    }
    if event.content != proof_content(request) {
        return Err("E_PROOF_NOT_FOR_REQUEST");
    }
    let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    if tags != proof_tags(request) {
        return Err("E_PROOF_NOT_FOR_REQUEST");
    }
    if event.created_at.as_secs().abs_diff(now_secs) > FRESHNESS_SECS {
        return Err("E_PROOF_EXPIRED");
    }
    Ok(())
}

/// Keep only a short, stable machine code from the registry; never display
/// free text from the network.
fn sanitize_code(value: Option<&serde_json::Value>) -> Option<String> {
    let code = value?.as_str()?;
    (!code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    .then(|| code.to_string())
}

/// Turn the registry's answer into an outcome. Only an exact `verified: true`
/// for this prover, key, event and kind counts; `verified: false` is a
/// rejection even with HTTP 200.
pub(crate) fn interpret_registry_response(
    status: u16,
    body: &[u8],
    request: &VerifyRequest,
    event: &Event,
    checked_at: u64,
) -> VerifyOutcome {
    let Ok(serde_json::Value::Object(body)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return if status >= 500 || status == 429 {
            unavailable("E_REGISTRY_UNAVAILABLE")
        } else {
            unavailable("E_REGISTRY_RESPONSE")
        };
    };

    if status == 200 && body.get("verified") == Some(&serde_json::Value::Bool(true)) {
        let field = |key: &str| body.get(key).and_then(serde_json::Value::as_str);
        let matches = field("identity") == Some(request.prover.as_str())
            && field("scheme") == Some("nostr")
            && field("nostr_pubkey") == Some(event.pubkey.to_hex().as_str())
            && field("event_id") == Some(event.id.to_hex().as_str())
            && body.get("kind").and_then(serde_json::Value::as_u64) == Some(PROOF_KIND as u64);
        if !matches {
            return rejected("E_REGISTRY_MISMATCH");
        }
        let link = body.get("link");
        let proof_id = link
            .and_then(|link| link.get("proof_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let incarnation = link
            .and_then(|link| link.get("incarnation"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| is_lower_hex(value, 32))
            .map(str::to_string);
        return VerifyOutcome::Verified {
            identity: request.prover.clone(),
            verifier: request.verifier.clone(),
            nostr_pubkey: request.prover_pubkey.clone(),
            event_id: event.id.to_hex(),
            proof_id,
            incarnation,
            checked_at,
            reputation: parse_reputation(body.get("reputation")),
            blue_tick: body.get("blue_tick").and_then(serde_json::Value::as_bool),
        };
    }

    let code = sanitize_code(body.get("code"));
    if status >= 500 || status == 429 {
        return unavailable(code.as_deref().unwrap_or("E_REGISTRY_UNAVAILABLE"));
    }
    rejected(code.as_deref().unwrap_or("E_REGISTRY_REJECTED"))
}

// ── Registry client ─────────────────────────────────────────────────────────

fn registry_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("registry client: {e}"))?;
    Ok(CLIENT.get_or_init(|| client))
}

async fn verify_with_registry(request: &VerifyRequest, event: &Event) -> VerifyOutcome {
    let Ok(event_value) = serde_json::from_str::<serde_json::Value>(&event.as_json()) else {
        return rejected("E_PROOF_MALFORMED");
    };
    let body = serde_json::json!({
        "scheme": "nostr",
        "event": event_value,
        "domain": request.prover,
    });
    let client = match registry_client() {
        Ok(client) => client,
        Err(_) => return unavailable("E_REGISTRY_UNREACHABLE"),
    };
    let response = match client.post(REGISTRY_VERIFY_URL).json(&body).send().await {
        Ok(response) => response,
        Err(_) => return unavailable("E_REGISTRY_UNREACHABLE"),
    };
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|len| len > MAX_REGISTRY_RESPONSE_BYTES as u64)
    {
        return unavailable("E_REGISTRY_RESPONSE");
    }
    let bytes = match response.bytes().await {
        Ok(bytes) if bytes.len() <= MAX_REGISTRY_RESPONSE_BYTES => bytes,
        _ => return unavailable("E_REGISTRY_RESPONSE"),
    };
    interpret_registry_response(status, &bytes, request, event, now_secs())
}

// ── Relay reads ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let s = tag.as_slice();
        (s.len() >= 2 && s[0] == name).then(|| s[1].as_str())
    })
}

/// The event a reply answers: its NIP-10 `reply` marker, else its `root`.
fn parent_event_id(event: &Event) -> Option<String> {
    let mut root = None;
    for tag in event.tags.iter() {
        let s = tag.as_slice();
        if s.len() >= 4 && s[0] == "e" {
            match s[3].as_str() {
                "reply" => return Some(s[1].clone()),
                "root" => root = Some(s[1].clone()),
                _ => {}
            }
        }
    }
    root
}

async fn fetch_message(state: &AppState, event_id: &str) -> Result<Event, String> {
    if !is_lower_hex(event_id, 64) {
        return Err("invalid event id".into());
    }
    let events = query_relay(
        state,
        &[serde_json::json!({ "ids": [event_id], "kinds": MESSAGE_KINDS, "limit": 1 })],
    )
    .await?;
    let event = events
        .into_iter()
        .next()
        .ok_or_else(|| "message not found".to_string())?;
    if event.id.to_hex() != event_id || !event.verify_id() || !event.verify_signature() {
        return Err("message failed verification".into());
    }
    Ok(event)
}

/// Read a request message from the relay and confirm the verifier it names
/// actually signed it.
async fn fetch_request(state: &AppState, event_id: &str) -> Result<(Event, VerifyRequest), String> {
    let event = fetch_message(state, event_id).await?;
    let request = parse_request(&event.content)?;
    if event.pubkey.to_hex() != request.verifier_pubkey {
        return Err("request was not sent by the verifier it names".into());
    }
    Ok((event, request))
}

fn managed_agent_keys(app: &AppHandle, state: &AppState, pubkey: &str) -> Result<Keys, String> {
    let record = {
        let _store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let mut records = load_managed_agents(app)?;
        find_managed_agent_mut(&mut records, pubkey)?.clone()
    };
    let keys = Keys::parse(record.private_key_nsec.trim())
        .map_err(|_| "managed agent key is unavailable".to_string())?;
    if keys.public_key().to_hex() != pubkey {
        return Err("managed agent key does not match its public key".into());
    }
    Ok(keys)
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Post a verification request from a managed verifier agent.
#[tauri::command]
pub async fn agent_verify_send_request(
    verifier_agent_pubkey: String,
    verifier_domain: String,
    prover_pubkey: String,
    prover_domain: String,
    channel_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SendChannelMessageResponse, String> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("nonce: {e}"))?;
    let request = VerifyRequest {
        verifier: verifier_domain.trim().to_ascii_lowercase(),
        verifier_pubkey: verifier_agent_pubkey.trim().to_ascii_lowercase(),
        prover: prover_domain.trim().to_ascii_lowercase(),
        prover_pubkey: prover_pubkey.trim().to_ascii_lowercase(),
        nonce: hex::encode(nonce),
    };
    let content = format_request(&request)?;
    send_managed_agent_channel_message(
        request.verifier_pubkey.clone(),
        channel_id,
        content,
        None,
        None,
        None,
        None,
        None,
        app,
        state,
    )
    .await
}

/// Answer a verification request as the managed prover agent it names.
#[tauri::command]
pub async fn agent_verify_send_proof(
    request_event_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SendChannelMessageResponse, String> {
    let request_event_id = request_event_id.trim().to_ascii_lowercase();
    let (request_event, request) = fetch_request(&state, &request_event_id).await?;
    let channel_id = tag_value(&request_event, "h")
        .ok_or("request has no channel")?
        .to_string();
    let keys = managed_agent_keys(&app, &state, &request.prover_pubkey)?;
    let event = tauri::async_runtime::spawn_blocking(move || {
        build_proof_event(&keys, &request, now_secs())
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))??;
    let prover_pubkey = event.pubkey.to_hex();
    send_managed_agent_channel_message(
        prover_pubkey,
        channel_id,
        format_proof(&event),
        None,
        None,
        None,
        Some(request_event_id),
        None,
        app,
        state,
    )
    .await
}

/// Check a proof message against the request it answers and the registry.
/// The app reaches this through the behavior read, which shows identity
/// separately from standing.
pub(crate) async fn check_proof(
    state: &AppState,
    proof_event_id: &str,
) -> Result<VerifyOutcome, String> {
    let proof_message = fetch_message(state, &proof_event_id.trim().to_ascii_lowercase()).await?;
    let event = match parse_proof(&proof_message.content) {
        Ok(event) => event,
        Err(_) => return Ok(rejected("E_PROOF_MALFORMED")),
    };
    let Some(request_id) = parent_event_id(&proof_message) else {
        return Ok(rejected("E_PROOF_NO_REQUEST"));
    };
    let (request_event, request) = match fetch_request(state, &request_id).await {
        Ok(found) => found,
        Err(_) => return Ok(rejected("E_PROOF_NO_REQUEST")),
    };
    if tag_value(&request_event, "h") != tag_value(&proof_message, "h") {
        return Ok(rejected("E_PROOF_NO_REQUEST"));
    }
    if let Err(code) = check_binding(&event, &request, now_secs()) {
        return Ok(rejected(code));
    }
    Ok(verify_with_registry(&request, &event).await)
}

#[cfg(test)]
#[path = "agent_verify_tests.rs"]
mod tests;
