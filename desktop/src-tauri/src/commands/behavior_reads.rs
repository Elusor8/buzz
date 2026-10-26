//! Native client for the receiving owner's behavior-standing reads.
//!
//! Buzz presents what its owner's service reports about a peer agent. It
//! never enforces, never wraps a runtime, never calls recovery and never
//! writes: the contract has only four authenticated GET reads.
//!
//! The owner provisions two things out of band: a non-secret read binding
//! (service origin, TLS trust, scopes, and the peer identities it covers) and
//! an opaque read token. The token goes straight into the OS keyring from a
//! file the user picks in a native dialog; the webview never sees it. Without
//! the keyring there are no reads.
//!
//! A peer is read only after its identity passes the native proof check
//! against the registry and matches one owner-provisioned subject exactly.
//! Every failure is shown as unavailable or unverified, never as a behavior
//! verdict.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use super::agent_verify::{check_proof, VerifyOutcome};
use super::behavior_wire::{
    is_read_token, is_subject_agent_id, parse_binding, read_error_code, DeniedAttempt, ListPage,
    ListRecord, OwnerNotification, ReadBinding, RestorationReceipt, Scope, StandingRead, TrustMode,
};
use crate::app_state::{keyring_service, AppState};
use crate::managed_agents::atomic_write_json_restricted;
use crate::secret_store::SecretStore;

const BINDING_FILE: &str = "behavior-read-binding.json";
const MAX_BINDING_BYTES: u64 = 256 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Paging a peer's lists stays allowed for the server's cursor lifetime after
/// the identity gate passed.
const GATE_TTL_MS: u64 = 15 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

// ── Local binding storage ───────────────────────────────────────────────────

fn binding_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "app data directory unavailable".to_string())?;
    Ok(dir.join(BINDING_FILE))
}

fn read_capped(path: &std::path::Path, cap: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|_| "file unreadable".to_string())?;
    if !meta.is_file() || meta.len() > cap {
        return Err("file too large or not a file".into());
    }
    std::fs::read(path).map_err(|_| "file unreadable".to_string())
}

enum StoredBinding {
    None,
    Invalid,
    Present(Box<ReadBinding>),
}

fn load_binding(app: &AppHandle) -> Result<StoredBinding, String> {
    let path = binding_path(app)?;
    if !path.exists() {
        return Ok(StoredBinding::None);
    }
    Ok(
        match read_capped(&path, MAX_BINDING_BYTES).and_then(|b| parse_binding(&b)) {
            Ok(binding) => StoredBinding::Present(Box::new(binding)),
            Err(_) => StoredBinding::Invalid,
        },
    )
}

fn secret_store() -> &'static SecretStore {
    SecretStore::shared(keyring_service())
}

fn load_token(binding: &ReadBinding) -> Result<String, &'static str> {
    match secret_store().load(&binding.secret_key()) {
        Ok(Some(token)) if is_read_token(&token) => Ok(token),
        Ok(_) => Err("no_credential"),
        Err(_) => Err("secure_storage_unavailable"),
    }
}

/// Non-secret binding metadata for the app.
#[derive(Debug, Clone, Serialize)]
pub struct SubjectSummary {
    pub domain: String,
    pub subject_agent_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BindingStatus {
    None,
    Invalid,
    Expired {
        expires_at_ms: u64,
    },
    NoCredential,
    SecureStorageUnavailable,
    Active {
        owner_id: String,
        mailbox_id: String,
        base_url: String,
        scopes: Vec<String>,
        expires_at_ms: u64,
        subjects: Vec<SubjectSummary>,
    },
}

fn status_of(stored: &StoredBinding, now: u64) -> BindingStatus {
    let binding = match stored {
        StoredBinding::None => return BindingStatus::None,
        StoredBinding::Invalid => return BindingStatus::Invalid,
        StoredBinding::Present(binding) => binding,
    };
    if !binding.is_live(now) {
        return BindingStatus::Expired {
            expires_at_ms: binding.expires_at_ms,
        };
    }
    match load_token(binding) {
        Err("secure_storage_unavailable") => BindingStatus::SecureStorageUnavailable,
        Err(_) => BindingStatus::NoCredential,
        Ok(_) => BindingStatus::Active {
            owner_id: binding.owner_id.clone(),
            mailbox_id: binding.mailbox_id.clone(),
            base_url: binding.base_url.clone(),
            scopes: binding.credential.scopes.clone(),
            expires_at_ms: binding.expires_at_ms,
            subjects: binding
                .subjects
                .iter()
                .map(|row| SubjectSummary {
                    domain: row.domain.clone(),
                    subject_agent_id: row.subject_agent_id.clone(),
                })
                .collect(),
        },
    }
}

/// A live binding with its token, or the reason reads are unavailable.
fn active_binding(app: &AppHandle) -> Result<(ReadBinding, String), String> {
    let stored = load_binding(app)?;
    let StoredBinding::Present(binding) = stored else {
        return Err("no_binding".into());
    };
    let binding = *binding;
    if !binding.is_live(now_ms()) {
        return Err("binding_expired".into());
    }
    let token = load_token(&binding).map_err(str::to_string)?;
    Ok((binding, token))
}

// ── HTTP ────────────────────────────────────────────────────────────────────

fn client_for(binding: &ReadBinding) -> Result<reqwest::Client, &'static str> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        // TLS 1.3 only. reqwest never sends 0-RTT early data by default.
        .tls_version_min(reqwest::tls::Version::TLS_1_3)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT);
    if binding.tls.trust_mode == TrustMode::OwnerCa {
        let pem = binding.tls.owner_ca_pem.as_deref().ok_or("tls_config")?;
        let certs =
            reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_err(|_| "tls_config")?;
        builder = builder.tls_certs_only(certs);
    }
    builder.build().map_err(|_| "tls_config")
}

fn has_header(response: &reqwest::Response, name: &str, check: impl Fn(&str) -> bool) -> bool {
    response
        .headers()
        .get_all(name)
        .iter()
        .any(|value| value.to_str().is_ok_and(&check))
}

/// GET one read. Returns the body on 200, otherwise a frozen error code.
async fn get(
    binding: &ReadBinding,
    token: &str,
    path: &str,
    cursor: Option<&str>,
) -> Result<Vec<u8>, String> {
    let client = client_for(binding)?;
    let mut request = client
        .get(format!("{}{}", binding.base_url, path))
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(cursor) = cursor {
        request = request.query(&[("cursor", cursor)]);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| "unreachable".to_string())?;
    let status = response.status().as_u16();
    let well_formed = has_header(&response, "content-type", |v| {
        v.split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
    }) && has_header(&response, "cache-control", |v| {
        v.split(',')
            .any(|d| d.trim().eq_ignore_ascii_case("no-store"))
    });
    if !well_formed
        || response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err("unexpected_response".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "unreachable".to_string())?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("unexpected_response".into());
        }
        body.extend_from_slice(&chunk);
    }
    if status == 200 {
        Ok(body)
    } else {
        Err(read_error_code(status, &body).to_string())
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReadResult<T> {
    Ok {
        data: T,
    },
    /// The credential does not carry this read's scope.
    NotGranted,
    /// The read failed; `code` is a frozen error code or a local one.
    Error {
        code: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct StandingView {
    #[serde(flatten)]
    pub read: StandingRead,
    /// Verified and still inside `fresh_until_ms` when read.
    pub current: bool,
}

const STANDING_SCOPE: &str = "standing:read";
const AUDIT_SCOPE: &str = "audit:read";
const NOTIFICATIONS_SCOPE: &str = "notifications:read";
const RECOVERY_SCOPE: &str = "recovery:read";

fn peer_path(binding: &ReadBinding, subject: &str, leaf: &str) -> String {
    format!(
        "/v1/mailboxes/{}/peers/{}/{}",
        binding.mailbox_id, subject, leaf
    )
}

async fn read_standing(
    binding: &ReadBinding,
    token: &str,
    subject: &str,
) -> ReadResult<StandingView> {
    if !binding.has_scope(STANDING_SCOPE) {
        return ReadResult::NotGranted;
    }
    let body = match get(
        binding,
        token,
        &peer_path(binding, subject, "standing"),
        None,
    )
    .await
    {
        Ok(body) => body,
        Err(code) => return ReadResult::Error { code },
    };
    let Ok(read) = serde_json::from_slice::<StandingRead>(&body) else {
        return ReadResult::Error {
            code: "invalid_response".into(),
        };
    };
    if read
        .validate(&binding.owner_id, &binding.mailbox_id, subject)
        .is_err()
    {
        return ReadResult::Error {
            code: "invalid_response".into(),
        };
    }
    let current = read.is_current(now_ms());
    ReadResult::Ok {
        data: StandingView { read, current },
    }
}

/// Where the previous page of a traversal ended.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagePosition {
    pub cursor: String,
    pub as_of_ms: u64,
    pub last_time_ms: u64,
    pub last_id: String,
}

async fn read_list<T>(
    binding: &ReadBinding,
    token: &str,
    scope_name: &str,
    path: &str,
    subject: Option<&str>,
    position: Option<&PagePosition>,
) -> ReadResult<ListPage<T>>
where
    T: ListRecord + serde::de::DeserializeOwned,
{
    if !binding.has_scope(scope_name) {
        return ReadResult::NotGranted;
    }
    let body = match get(binding, token, path, position.map(|p| p.cursor.as_str())).await {
        Ok(body) => body,
        Err(code) => return ReadResult::Error { code },
    };
    let Ok(page) = serde_json::from_slice::<ListPage<T>>(&body) else {
        return ReadResult::Error {
            code: "invalid_response".into(),
        };
    };
    let scope = Scope {
        owner_id: &binding.owner_id,
        mailbox_id: &binding.mailbox_id,
        subject_agent_id: subject,
    };
    let previous = position.map(|p| (p.as_of_ms, (p.last_time_ms, p.last_id.as_str())));
    if page.validate(&scope, previous).is_err() {
        return ReadResult::Error {
            code: "invalid_response".into(),
        };
    }
    ReadResult::Ok { data: page }
}

// ── Identity gate ───────────────────────────────────────────────────────────

/// Subjects whose identity passed the gate, with when.
fn gated_subjects() -> &'static Mutex<HashMap<String, u64>> {
    static GATED: std::sync::OnceLock<Mutex<HashMap<String, u64>>> = std::sync::OnceLock::new();
    GATED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn subject_is_gated(subject: &str, now: u64) -> bool {
    gated_subjects()
        .lock()
        .map(|map| {
            map.get(subject)
                .is_some_and(|at| now.saturating_sub(*at) < GATE_TTL_MS)
        })
        .unwrap_or(false)
}

/// How a verified identity maps onto the owner's provisioned subjects.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SubjectMatch {
    /// The identity check did not verify, so nothing is attributed.
    IdentityNotVerified,
    /// The registry did not report a usable link incarnation.
    NoIncarnation,
    /// The owner has not provisioned this agent's key.
    NotProvisioned,
    /// The provisioned row disagrees with the registry.
    Mismatch,
    Matched {
        domain: String,
        subject_agent_id: String,
    },
}

/// Match a verified identity to exactly one owner-provisioned subject row.
pub(crate) fn match_subject(binding: &ReadBinding, outcome: &VerifyOutcome) -> SubjectMatch {
    let VerifyOutcome::Verified {
        identity,
        nostr_pubkey,
        incarnation,
        ..
    } = outcome
    else {
        return SubjectMatch::IdentityNotVerified;
    };
    let Some(incarnation) = incarnation else {
        return SubjectMatch::NoIncarnation;
    };
    let Some(row) = binding
        .subjects
        .iter()
        .find(|row| &row.nostr_pubkey == nostr_pubkey)
    else {
        return SubjectMatch::NotProvisioned;
    };
    if &row.domain != identity || &row.incarnation != incarnation {
        return SubjectMatch::Mismatch;
    }
    // The binding was validated on load, so the row's subject id already
    // equals the derivation from (domain, incarnation).
    SubjectMatch::Matched {
        domain: row.domain.clone(),
        subject_agent_id: row.subject_agent_id.clone(),
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn behavior_binding_status(app: AppHandle) -> Result<BindingStatus, String> {
    Ok(status_of(&load_binding(&app)?, now_ms()))
}

async fn pick_file(
    app: &AppHandle,
    title: &str,
    extensions: &[&str],
) -> Result<Option<PathBuf>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut dialog = app.dialog().file().set_title(title);
    if !extensions.is_empty() {
        dialog = dialog.add_filter("Read access", extensions);
    }
    dialog.pick_file(move |path| {
        let _ = sender.send(path);
    });
    let Some(file_path) = receiver
        .await
        .map_err(|_| "file picker closed unexpectedly".to_string())?
    else {
        return Ok(None);
    };
    file_path
        .as_path()
        .map(|p| Some(p.to_path_buf()))
        .ok_or_else(|| "the selected path is invalid".to_string())
}

/// Import an owner-provisioned binding and its read token. Both files are
/// picked and read natively; the token goes only to the OS keyring.
#[tauri::command]
pub async fn behavior_import_binding(app: AppHandle) -> Result<BindingStatus, String> {
    let Some(binding_file) = pick_file(&app, "Choose the read binding file", &["json"]).await?
    else {
        return behavior_binding_status(app);
    };
    let binding = parse_binding(&read_capped(&binding_file, MAX_BINDING_BYTES)?)
        .map_err(|_| "That file is not a valid read binding.".to_string())?;
    if !binding.is_live(now_ms()) {
        return Err("That read binding has expired. Ask the owner to reissue it.".into());
    }
    let Some(token_file) = pick_file(&app, "Choose the read token file", &[]).await? else {
        return behavior_binding_status(app);
    };
    let raw = read_capped(&token_file, MAX_TOKEN_FILE_BYTES)?;
    let token = std::str::from_utf8(&raw)
        .ok()
        .map(|text| text.trim_end_matches(['\n', '\r']))
        .filter(|text| is_read_token(text))
        .ok_or_else(|| "That file is not a valid read token.".to_string())?
        .to_string();

    let store = secret_store();
    let previous = match load_binding(&app)? {
        StoredBinding::Present(old) => Some(old.secret_key()),
        _ => None,
    };
    store.store(&binding.secret_key(), &token).map_err(|_| {
        "Secure storage is unavailable, so read access cannot be set up.".to_string()
    })?;
    let payload = serde_json::to_vec_pretty(&binding).map_err(|e| e.to_string())?;
    let path = binding_path(&app)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|_| "app data directory unavailable".to_string())?;
    }
    if let Err(error) = atomic_write_json_restricted(&path, &payload) {
        let _ = store.delete(&binding.secret_key());
        return Err(error);
    }
    if let Some(old_key) = previous.filter(|key| *key != binding.secret_key()) {
        let _ = store.delete(&old_key);
    }
    if let Ok(mut gated) = gated_subjects().lock() {
        gated.clear();
    }
    behavior_binding_status(app)
}

/// Remove local read access. This deletes the local token and binding only;
/// the owner must still revoke the credential on their side.
#[tauri::command]
pub fn behavior_remove_binding(app: AppHandle) -> Result<BindingStatus, String> {
    if let StoredBinding::Present(binding) = load_binding(&app)? {
        secret_store()
            .delete(&binding.secret_key())
            .map_err(|_| "Secure storage is unavailable; the token was not removed.".to_string())?;
    }
    let path = binding_path(&app)?;
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|_| "The binding file could not be removed.".to_string())?;
    }
    if let Ok(mut gated) = gated_subjects().lock() {
        gated.clear();
    }
    Ok(BindingStatus::None)
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerBehavior {
    pub identity: VerifyOutcome,
    pub subject: SubjectMatch,
    pub standing: ReadResult<StandingView>,
    pub denied_attempts: ReadResult<ListPage<DeniedAttempt>>,
    pub recovery_receipts: ReadResult<ListPage<RestorationReceipt>>,
}

fn skipped<T>(code: &str) -> ReadResult<T> {
    ReadResult::Error { code: code.into() }
}

/// Check a proof's identity, then read the owner's behavior records for that
/// peer. Nothing is read unless the identity maps to one provisioned subject.
#[tauri::command]
pub async fn behavior_read_peer(
    proof_event_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<PeerBehavior, String> {
    let identity = check_proof(&state, &proof_event_id).await?;
    let (binding, token) = match active_binding(&app) {
        Ok(found) => found,
        Err(code) => {
            return Ok(PeerBehavior {
                identity,
                subject: SubjectMatch::IdentityNotVerified,
                standing: skipped(&code),
                denied_attempts: skipped(&code),
                recovery_receipts: skipped(&code),
            })
        }
    };
    let subject = match_subject(&binding, &identity);
    let SubjectMatch::Matched {
        subject_agent_id, ..
    } = &subject
    else {
        return Ok(PeerBehavior {
            identity,
            subject,
            standing: skipped("identity_unattributed"),
            denied_attempts: skipped("identity_unattributed"),
            recovery_receipts: skipped("identity_unattributed"),
        });
    };
    if let Ok(mut gated) = gated_subjects().lock() {
        gated.insert(subject_agent_id.clone(), now_ms());
    }
    let id = subject_agent_id.as_str();
    let denied_path = peer_path(&binding, id, "denied-attempts");
    let recovery_path = peer_path(&binding, id, "recovery-receipts");
    let (standing, denied_attempts, recovery_receipts) = tokio::join!(
        read_standing(&binding, &token, id),
        read_list::<DeniedAttempt>(&binding, &token, AUDIT_SCOPE, &denied_path, Some(id), None),
        read_list::<RestorationReceipt>(
            &binding,
            &token,
            RECOVERY_SCOPE,
            &recovery_path,
            Some(id),
            None,
        ),
    );
    Ok(PeerBehavior {
        identity,
        subject,
        standing,
        denied_attempts,
        recovery_receipts,
    })
}

fn to_json<T: Serialize>(value: T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// Read one page of a list. `notifications` is mailbox-wide; the peer lists
/// need a subject that passed the identity gate recently. `position` is where
/// the previous page ended, or `None` for the first notifications page.
#[tauri::command]
pub async fn behavior_read_list(
    list: String,
    subject_agent_id: Option<String>,
    position: Option<PagePosition>,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    let (binding, token) = match active_binding(&app) {
        Ok(found) => found,
        Err(code) => return to_json(skipped::<()>(&code)),
    };
    if list == "notifications" {
        let path = format!("/v1/mailboxes/{}/notifications", binding.mailbox_id);
        return to_json(
            read_list::<OwnerNotification>(
                &binding,
                &token,
                NOTIFICATIONS_SCOPE,
                &path,
                None,
                position.as_ref(),
            )
            .await,
        );
    }
    let (Some(id), Some(position)) = (subject_agent_id.as_deref(), position.as_ref()) else {
        return Err("a peer list page needs a subject and a position".into());
    };
    if !is_subject_agent_id(id) || !subject_is_gated(id, now_ms()) {
        return to_json(skipped::<()>("identity_unattributed"));
    }
    match list.as_str() {
        "denied_attempts" => to_json(
            read_list::<DeniedAttempt>(
                &binding,
                &token,
                AUDIT_SCOPE,
                &peer_path(&binding, id, "denied-attempts"),
                Some(id),
                Some(position),
            )
            .await,
        ),
        "recovery_receipts" => to_json(
            read_list::<RestorationReceipt>(
                &binding,
                &token,
                RECOVERY_SCOPE,
                &peer_path(&binding, id, "recovery-receipts"),
                Some(id),
                Some(position),
            )
            .await,
        ),
        _ => Err("unknown list".into()),
    }
}

#[cfg(test)]
#[path = "behavior_reads_tests.rs"]
mod tests;
