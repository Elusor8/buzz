//! Wire types for the receiving owner's behavior-standing reads.
//!
//! Buzz only reads and presents. Every type here decodes strictly: unknown or
//! duplicate keys, missing keys, wrong nullability, out-of-range integers and
//! unknown enum values are rejected, and the caller shows the read as
//! unavailable. Nothing is computed, defaulted or inferred locally; in
//! particular Buzz never intersects policies, calculates quotas or turns a
//! failed read into a behavior verdict.

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const SCHEMA_VERSION: &str = "1.0";
/// Largest integer JSON readers agree on (2^53 - 1).
pub(crate) const MAX_UINT: u64 = 9_007_199_254_740_991;
pub(crate) const MAX_GRANT_MS: u64 = 86_400_000;
pub(crate) const MAX_PAGE_ITEMS: usize = 100;
pub(crate) const MAX_CURSOR_LEN: usize = 2048;
pub(crate) const REGISTRY_ORIGIN: &str = "https://api.zipviz.ai";
const SUBJECT_ID_DOMAIN: &[u8] = b"ZipViz subject-id v1";
const TOKEN_PREFIX: &str = "mbr1_";

pub(crate) const SCOPES: [&str; 4] = [
    "standing:read",
    "audit:read",
    "notifications:read",
    "recovery:read",
];

// ── Field helpers ───────────────────────────────────────────────────────────

/// A nullable field that must still be present (`null` or a value).
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// An optional field that is either absent or a non-null value.
fn absent_or_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn check(condition: bool, what: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("invalid {what}"))
    }
}

fn uint(value: u64, what: &str) -> Result<(), String> {
    check(value <= MAX_UINT, what)
}

fn positive_uint(value: u64, what: &str) -> Result<(), String> {
    check((1..=MAX_UINT).contains(&value), what)
}

pub(crate) fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn is_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let ok = match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn is_base64url(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Opaque identifiers (owner, principal, artifact ids): bounded, printable,
/// no whitespace. Their inner format belongs to the issuer.
fn is_opaque_id(value: &str) -> bool {
    (1..=128).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
}

/// The frozen canonical `.viz` name pattern:
/// `^[a-z0-9][a-z0-9-]{0,19}\.(?:[a-z0-9][a-z0-9-]{0,19}\.)?viz$`.
pub(crate) fn is_canonical_viz(value: &str) -> bool {
    fn label(part: &str) -> bool {
        let bytes = part.as_bytes();
        (1..=20).contains(&bytes.len())
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    }
    let Some(stem) = value.strip_suffix(".viz") else {
        return false;
    };
    let parts: Vec<&str> = stem.split('.').collect();
    (1..=2).contains(&parts.len()) && parts.iter().all(|part| label(part))
}

/// Derive the stable subject id for a registry identity (frozen v1
/// derivation): `sub1_` + base64url(SHA-256("ZipViz subject-id v1" || 0x00 ||
/// JCS({registry_origin, domain, incarnation}))).
pub(crate) fn derive_subject_agent_id(domain: &str, incarnation: &str) -> Result<String, String> {
    check(is_canonical_viz(domain), "domain")?;
    check(is_lower_hex(incarnation, 32), "incarnation")?;
    // RFC 8785 for an object of three ASCII strings: keys in code-unit order,
    // no whitespace. Both values are validated ASCII with nothing to escape.
    let canonical = format!(
        "{{\"domain\":{},\"incarnation\":{},\"registry_origin\":{}}}",
        serde_json::to_string(domain).map_err(|e| e.to_string())?,
        serde_json::to_string(incarnation).map_err(|e| e.to_string())?,
        serde_json::to_string(REGISTRY_ORIGIN).map_err(|e| e.to_string())?,
    );
    let mut hasher = Sha256::new();
    hasher.update(SUBJECT_ID_DOMAIN);
    hasher.update([0u8]);
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(format!(
        "sub1_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    ))
}

pub(crate) fn is_subject_agent_id(value: &str) -> bool {
    value
        .strip_prefix("sub1_")
        .is_some_and(|rest| rest.len() == 43 && is_base64url(rest))
}

/// A read bearer is `mbr1_` plus 32 random bytes as unpadded base64url.
pub(crate) fn is_read_token(value: &str) -> bool {
    value.strip_prefix(TOKEN_PREFIX).is_some_and(|rest| {
        rest.len() == 43
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(rest)
                .is_ok_and(|bytes| bytes.len() == 32)
    })
}

/// `https://` plus a canonical lowercase host and optional non-default port,
/// nothing else.
pub(crate) fn is_canonical_https_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.origin().ascii_serialization() == value
}

// ── Shared shapes ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    Normal,
    Notify,
    Reduced,
    Denied,
    Calibrating,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start_ms: u64,
    pub end_ms: u64,
}

impl Window {
    fn validate(&self) -> Result<(), String> {
        uint(self.start_ms, "window")?;
        uint(self.end_ms, "window")?;
        check(self.start_ms < self.end_ms, "window")
    }
}

/// Signature metadata of a signed artifact. Buzz holds no issuer keys, so it
/// shows that an artifact is signed and by which key id; it does not claim to
/// have verified the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub alg: String,
    pub key_id: String,
    pub value_base64url: String,
}

impl Signature {
    fn validate(&self) -> Result<(), String> {
        check(self.alg == "Ed25519", "signature alg")?;
        check(is_opaque_id(&self.key_id), "signature key id")?;
        let decoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.value_base64url);
        check(
            is_base64url(&self.value_base64url) && decoded.is_ok_and(|b| b.len() == 64),
            "signature value",
        )
    }
}

fn validate_signed_common(
    schema_version: &str,
    kind: &str,
    expected_kind: &str,
    id: &str,
    issued_at_ms: u64,
    signature: &Signature,
) -> Result<(), String> {
    check(schema_version == SCHEMA_VERSION, "schema version")?;
    check(kind == expected_kind, "type")?;
    check(is_opaque_id(id), "id")?;
    uint(issued_at_ms, "issued_at_ms")?;
    signature.validate()
}

fn is_digest(value: &str) -> bool {
    is_opaque_id(value)
}

fn unique<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(index, item)| !items[..index].contains(item))
}

// ── Standing read ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityValidity {
    Valid,
    Invalid,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    NotMeasured,
    Stale,
    Unavailable,
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionBasis {
    Current,
    LastKnown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRef {
    pub id: String,
    pub basis: DecisionBasis,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveAllowance {
    pub max_turns_per_conversation: u64,
    pub max_new_conversations_per_hour: u64,
    pub max_actions_per_hour: u64,
    pub permitted_action_classes: Vec<String>,
    pub rate_limit_per_hour: u64,
}

impl EffectiveAllowance {
    fn is_zero(&self) -> bool {
        self.max_turns_per_conversation == 0
            && self.max_new_conversations_per_hour == 0
            && self.max_actions_per_hour == 0
            && self.rate_limit_per_hour == 0
            && self.permitted_action_classes.is_empty()
    }
}

/// Action classes are neutral registry identifiers, never content.
fn is_action_class(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingRead {
    pub schema_version: String,
    pub as_of_ms: u64,
    pub owner_id: String,
    pub mailbox_id: String,
    pub subject_agent_id: String,
    pub identity_validity: IdentityValidity,
    pub standing: Standing,
    #[serde(deserialize_with = "required_nullable")]
    pub decision_ref: Option<DecisionRef>,
    #[serde(deserialize_with = "required_nullable")]
    pub evidence_version: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub window: Option<Window>,
    #[serde(deserialize_with = "required_nullable")]
    pub policy_version: Option<u64>,
    pub effective_allowance: EffectiveAllowance,
    pub executable: bool,
    pub checked_at_ms: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub fresh_until_ms: Option<u64>,
    pub verification_status: VerificationStatus,
    #[serde(deserialize_with = "required_nullable")]
    pub reason_code: Option<String>,
}

impl StandingRead {
    /// Check every frozen invariant. A response that breaks one is shown as
    /// unavailable, never repaired.
    pub(crate) fn validate(
        &self,
        owner_id: &str,
        mailbox_id: &str,
        subject_agent_id: &str,
    ) -> Result<(), String> {
        check(self.schema_version == SCHEMA_VERSION, "schema version")?;
        check(self.owner_id == owner_id, "owner")?;
        check(self.mailbox_id == mailbox_id, "mailbox")?;
        check(self.subject_agent_id == subject_agent_id, "subject")?;
        uint(self.as_of_ms, "as_of_ms")?;
        uint(self.checked_at_ms, "checked_at_ms")?;
        check(self.checked_at_ms <= self.as_of_ms, "checked_at_ms")?;

        let allowance = &self.effective_allowance;
        for cap in [
            allowance.max_turns_per_conversation,
            allowance.max_new_conversations_per_hour,
            allowance.max_actions_per_hour,
            allowance.rate_limit_per_hour,
        ] {
            uint(cap, "allowance")?;
        }
        check(
            allowance
                .permitted_action_classes
                .iter()
                .all(|c| is_action_class(c))
                && unique(&allowance.permitted_action_classes),
            "action classes",
        )?;

        match &self.decision_ref {
            Some(decision) => {
                check(is_opaque_id(&decision.id), "decision id")?;
                check(is_lower_hex(&decision.digest_sha256, 64), "decision digest")?;
                check(
                    self.evidence_version
                        .is_some_and(|v| positive_uint(v, "").is_ok())
                        && self
                            .policy_version
                            .is_some_and(|v| positive_uint(v, "").is_ok()),
                    "decision versions",
                )?;
                self.window.ok_or("invalid decision window")?.validate()?;
            }
            None => {
                check(
                    self.evidence_version.is_none()
                        && self.window.is_none()
                        && self.policy_version.is_none()
                        && self.standing == Standing::Unknown,
                    "absent decision",
                )?;
            }
        }

        let verified = self.verification_status == VerificationStatus::Verified;
        if verified {
            check(
                self.identity_validity == IdentityValidity::Valid,
                "verified identity",
            )?;
            check(
                self.decision_ref
                    .as_ref()
                    .is_some_and(|d| d.basis == DecisionBasis::Current),
                "verified decision basis",
            )?;
            check(self.reason_code.is_none(), "verified reason")?;
            let fresh_until = self.fresh_until_ms.ok_or("invalid verified freshness")?;
            uint(fresh_until, "fresh_until_ms")?;
            check(fresh_until > self.as_of_ms, "fresh_until_ms")?;
        } else {
            check(
                self.decision_ref
                    .as_ref()
                    .is_none_or(|d| d.basis == DecisionBasis::LastKnown),
                "unverified decision basis",
            )?;
        }

        let fail_closed = !verified || self.identity_validity != IdentityValidity::Valid;
        if fail_closed {
            check(
                !self.executable
                    && allowance.is_zero()
                    && self.fresh_until_ms.is_none()
                    && self.reason_code.as_deref() == Some("fail_closed"),
                "fail-closed snapshot",
            )?;
        }
        if self.standing == Standing::Denied {
            check(!self.executable && allowance.is_zero(), "denied allowance")?;
        }
        Ok(())
    }

    /// Whether this snapshot is still current at `now_ms`.
    pub(crate) fn is_current(&self, now_ms: u64) -> bool {
        self.verification_status == VerificationStatus::Verified
            && self.fresh_until_ms.is_some_and(|until| now_ms < until)
    }
}

// ── Reason code domains (registry profile 1) ────────────────────────────────

const DECISION_REASONS: [&str; 8] = [
    "behavior_shift",
    "owner_revoked",
    "calibration_incomplete",
    "not_measured",
    "stale",
    "unavailable",
    "unverifiable",
    "recovery_authorized",
];

const DENIAL_REASONS: [&str; 9] = [
    "standing_denied",
    "action_class_not_permitted",
    "turn_allowance_exhausted",
    "new_conversation_allowance_exhausted",
    "action_allowance_exhausted",
    "rate_limit_exhausted",
    "state_unverifiable",
    "fail_closed",
    "baseline_guard",
];

const REFUSAL_REASONS: [&str; 5] = [
    "expired",
    "replayed",
    "scope_mismatch",
    "unverifiable",
    "recovery_refused",
];

const NOTIFICATION_FAILURES: [&str; 6] = [
    "no_channel",
    "channel_unsupported",
    "owner_authority_unresolved",
    "timeout",
    "network_error",
    "channel_error",
];

/// Decision reasons must be in the decision domain and include one that
/// matches the standing; normal may carry none.
fn decision_reasons_match(standing: Standing, reasons: &[String]) -> bool {
    if reasons.len() > 8
        || !unique(reasons)
        || !reasons
            .iter()
            .all(|r| DECISION_REASONS.contains(&r.as_str()))
    {
        return false;
    }
    let has = |code: &str| reasons.iter().any(|r| r == code);
    if standing == Standing::Denied && has("recovery_authorized") {
        return false;
    }
    match standing {
        Standing::Normal => reasons.iter().all(|r| r == "recovery_authorized"),
        Standing::Notify | Standing::Reduced => has("behavior_shift"),
        Standing::Denied => has("behavior_shift") || has("owner_revoked"),
        Standing::Calibrating => has("calibration_incomplete"),
        Standing::Unknown => ["not_measured", "stale", "unavailable", "unverifiable"]
            .iter()
            .any(|code| has(code)),
    }
}

fn is_notification_failure(code: &str) -> bool {
    NOTIFICATION_FAILURES.contains(&code)
        || code
            .strip_prefix("http_")
            .and_then(|status| status.parse::<u16>().ok().filter(|_| status.len() == 3))
            .is_some_and(|status| (300..=599).contains(&status))
}

// ── List records ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedOutcome {
    Denied,
    NonExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedAttempt {
    pub schema_version: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub issued_at_ms: u64,
    pub signature: Signature,
    pub attempt_id: String,
    pub owner_id: String,
    pub mailbox_id: String,
    pub subject_agent_id: String,
    pub decision_id: String,
    pub policy_version: u64,
    pub attempted_action_class: String,
    #[serde(
        default,
        deserialize_with = "absent_or_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub conversation_id: Option<String>,
    pub timestamp_ms: u64,
    pub reason_code: String,
    pub outcome: DeniedOutcome,
    pub receipt_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    Retrying,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerNotification {
    pub notification_id: String,
    pub episode_id: String,
    pub owner_id: String,
    pub mailbox_id: String,
    pub subject_agent_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub decision_id: Option<String>,
    pub standing: Standing,
    pub reason_codes: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub evidence_version: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub window: Option<Window>,
    #[serde(deserialize_with = "required_nullable")]
    pub policy_version: Option<u64>,
    pub created_at_ms: u64,
    pub delivery_state: DeliveryState,
    pub attempt_count: u64,
    #[serde(
        default,
        deserialize_with = "absent_or_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_attempt_at_ms: Option<u64>,
    #[serde(
        default,
        deserialize_with = "absent_or_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub delivered_at_ms: Option<u64>,
    #[serde(
        default,
        deserialize_with = "absent_or_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorationResult {
    Restored,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorationReceipt {
    pub schema_version: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub recovery_authorization_id: String,
    pub previous_decision_id: String,
    pub new_decision_id: String,
    pub owner_id: String,
    pub mailbox_id: String,
    pub subject_agent_id: String,
    pub policy_version: u64,
    pub evidence_version: u64,
    pub window: Window,
    pub restored_allowance_digest: String,
    pub effective_at_ms: u64,
    pub authorization_digest: String,
    pub result: RestorationResult,
    pub reason_code: String,
    pub issued_at_ms: u64,
    pub signature: Signature,
}

/// Where a list record must belong, and how pages are ordered.
pub(crate) struct Scope<'a> {
    pub owner_id: &'a str,
    pub mailbox_id: &'a str,
    pub subject_agent_id: Option<&'a str>,
}

pub(crate) trait ListRecord: Sized {
    fn validate(&self, scope: &Scope<'_>) -> Result<(), String>;
    /// The frozen ascending sort key `(timestamp, tie-break id)`.
    fn sort_key(&self) -> (u64, &str);
}

fn same_partition(
    scope: &Scope<'_>,
    owner_id: &str,
    mailbox_id: &str,
    subject_agent_id: &str,
) -> Result<(), String> {
    check(owner_id == scope.owner_id, "record owner")?;
    check(mailbox_id == scope.mailbox_id, "record mailbox")?;
    check(is_subject_agent_id(subject_agent_id), "record subject")?;
    if let Some(subject) = scope.subject_agent_id {
        check(subject_agent_id == subject, "record subject")?;
    }
    Ok(())
}

impl ListRecord for DeniedAttempt {
    fn validate(&self, scope: &Scope<'_>) -> Result<(), String> {
        validate_signed_common(
            &self.schema_version,
            &self.kind,
            "mailbox.denied_attempt",
            &self.id,
            self.issued_at_ms,
            &self.signature,
        )?;
        same_partition(
            scope,
            &self.owner_id,
            &self.mailbox_id,
            &self.subject_agent_id,
        )?;
        for id in [&self.attempt_id, &self.decision_id, &self.receipt_id] {
            check(is_opaque_id(id), "record id")?;
        }
        if let Some(conversation) = &self.conversation_id {
            check(is_opaque_id(conversation), "conversation id")?;
        }
        positive_uint(self.policy_version, "policy version")?;
        uint(self.timestamp_ms, "timestamp")?;
        check(
            is_action_class(&self.attempted_action_class),
            "action class",
        )?;
        check(
            DENIAL_REASONS.contains(&self.reason_code.as_str()),
            "denial reason",
        )
    }

    fn sort_key(&self) -> (u64, &str) {
        (self.timestamp_ms, &self.attempt_id)
    }
}

impl ListRecord for OwnerNotification {
    fn validate(&self, scope: &Scope<'_>) -> Result<(), String> {
        same_partition(
            scope,
            &self.owner_id,
            &self.mailbox_id,
            &self.subject_agent_id,
        )?;
        check(is_opaque_id(&self.notification_id), "notification id")?;
        check(is_opaque_id(&self.episode_id), "episode id")?;
        uint(self.created_at_ms, "created_at_ms")?;
        uint(self.attempt_count, "attempt count")?;

        let fail_closed_notice = self.standing == Standing::Unknown
            && self.reason_codes == ["state_unverifiable", "fail_closed"];
        if fail_closed_notice {
            // Provenance may be null only on the fail-closed notice, and the
            // window and evidence version travel together.
            check(
                self.evidence_version.is_some() == self.window.is_some(),
                "notification provenance",
            )?;
        } else {
            check(
                self.decision_id.is_some()
                    && self.evidence_version.is_some()
                    && self.window.is_some()
                    && self.policy_version.is_some(),
                "notification provenance",
            )?;
            check(
                decision_reasons_match(self.standing, &self.reason_codes),
                "notification reasons",
            )?;
        }
        if let Some(decision) = &self.decision_id {
            check(is_opaque_id(decision), "decision id")?;
        }
        if let Some(version) = self.evidence_version {
            positive_uint(version, "evidence version")?;
        }
        if let Some(version) = self.policy_version {
            positive_uint(version, "policy version")?;
        }
        if let Some(window) = &self.window {
            window.validate()?;
        }
        if let Some(at) = self.last_attempt_at_ms {
            uint(at, "last attempt")?;
        }

        // Delivery is never inferred: only a delivered record carries a
        // delivery time, and a failed one says why.
        let delivered = self.delivery_state == DeliveryState::Delivered;
        check(self.delivered_at_ms.is_some() == delivered, "delivery time")?;
        if let Some(at) = self.delivered_at_ms {
            uint(at, "delivery time")?;
        }
        match (&self.failure_code, self.delivery_state) {
            (Some(_), DeliveryState::Delivered | DeliveryState::Queued) => {
                return Err("invalid failure code".into())
            }
            (None, DeliveryState::Failed) => return Err("invalid failure code".into()),
            (Some(code), _) => check(is_notification_failure(code), "failure code")?,
            (None, _) => {}
        }
        Ok(())
    }

    fn sort_key(&self) -> (u64, &str) {
        (self.created_at_ms, &self.notification_id)
    }
}

impl ListRecord for RestorationReceipt {
    fn validate(&self, scope: &Scope<'_>) -> Result<(), String> {
        validate_signed_common(
            &self.schema_version,
            &self.kind,
            "mailbox.restoration_receipt",
            &self.id,
            self.issued_at_ms,
            &self.signature,
        )?;
        same_partition(
            scope,
            &self.owner_id,
            &self.mailbox_id,
            &self.subject_agent_id,
        )?;
        for id in [
            &self.recovery_authorization_id,
            &self.previous_decision_id,
            &self.new_decision_id,
        ] {
            check(is_opaque_id(id), "record id")?;
        }
        check(
            is_digest(&self.restored_allowance_digest) && is_digest(&self.authorization_digest),
            "digest",
        )?;
        positive_uint(self.policy_version, "policy version")?;
        positive_uint(self.evidence_version, "evidence version")?;
        self.window.validate()?;
        uint(self.effective_at_ms, "effective_at_ms")?;
        match self.result {
            RestorationResult::Restored => check(self.reason_code == "restored", "receipt reason"),
            RestorationResult::Refused => check(
                REFUSAL_REASONS.contains(&self.reason_code.as_str()),
                "receipt reason",
            ),
        }
    }

    fn sort_key(&self) -> (u64, &str) {
        (self.issued_at_ms, &self.id)
    }
}

// ── List envelope ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPage<T> {
    pub schema_version: String,
    pub as_of_ms: u64,
    pub owner_id: String,
    pub mailbox_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub subject_agent_id: Option<String>,
    pub items: Vec<T>,
    #[serde(deserialize_with = "required_nullable")]
    pub next_cursor: Option<String>,
}

impl<T: ListRecord> ListPage<T> {
    /// Validate a page. `previous` is the last sort key and snapshot time of
    /// the page before, so a traversal stays on one ordered snapshot.
    pub(crate) fn validate(
        &self,
        scope: &Scope<'_>,
        previous: Option<(u64, (u64, &str))>,
    ) -> Result<(), String> {
        check(self.schema_version == SCHEMA_VERSION, "schema version")?;
        uint(self.as_of_ms, "as_of_ms")?;
        check(self.owner_id == scope.owner_id, "owner")?;
        check(self.mailbox_id == scope.mailbox_id, "mailbox")?;
        check(
            self.subject_agent_id.as_deref() == scope.subject_agent_id,
            "envelope subject",
        )?;
        check(self.items.len() <= MAX_PAGE_ITEMS, "page size")?;
        if self.items.is_empty() {
            check(self.next_cursor.is_none(), "empty page cursor")?;
        }
        if let Some(cursor) = &self.next_cursor {
            check(
                cursor.len() <= MAX_CURSOR_LEN && is_base64url(cursor),
                "cursor",
            )?;
        }
        let mut last = None;
        if let Some((as_of_ms, key)) = previous {
            check(self.as_of_ms == as_of_ms, "snapshot")?;
            last = Some(key);
        }
        for item in &self.items {
            item.validate(scope)?;
            let key = item.sort_key();
            if let Some(prev) = last {
                check(prev < key, "sort order")?;
            }
            last = Some(key);
        }
        Ok(())
    }
}

// ── Read binding descriptor ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    System,
    OwnerCa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsBinding {
    pub trust_mode: TrustMode,
    #[serde(deserialize_with = "required_nullable")]
    pub owner_ca_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMeta {
    pub credential_id: String,
    pub scopes: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRow {
    pub subject_agent_id: String,
    pub domain: String,
    pub incarnation: String,
    pub nostr_pubkey: String,
}

/// Owner-provisioned, non-secret configuration for the reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadBinding {
    pub schema_version: String,
    pub owner_id: String,
    pub principal_id: String,
    pub mailbox_id: String,
    pub base_url: String,
    pub tls: TlsBinding,
    pub credential: CredentialMeta,
    pub subjects: Vec<SubjectRow>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl ReadBinding {
    /// Validate the descriptor's shape. Expiry against the clock is checked
    /// separately so an expired binding can still be shown and removed.
    pub(crate) fn validate(&self) -> Result<(), String> {
        check(self.schema_version == SCHEMA_VERSION, "schema version")?;
        check(is_opaque_id(&self.owner_id), "owner id")?;
        check(is_opaque_id(&self.principal_id), "principal id")?;
        check(is_uuid_v4(&self.mailbox_id), "mailbox id")?;
        check(is_canonical_https_origin(&self.base_url), "base url")?;
        match (self.tls.trust_mode, &self.tls.owner_ca_pem) {
            (TrustMode::System, None) => {}
            (TrustMode::OwnerCa, Some(pem)) => check(
                reqwest::Certificate::from_pem_bundle(pem.as_bytes()).is_ok_and(|c| c.len() == 1),
                "owner CA",
            )?,
            _ => return Err("invalid tls".into()),
        }

        let credential = &self.credential;
        check(is_uuid_v4(&credential.credential_id), "credential id")?;
        check(
            unique(&credential.scopes)
                && credential
                    .scopes
                    .iter()
                    .all(|s| SCOPES.contains(&s.as_str())),
            "scopes",
        )?;
        uint(credential.expires_at_ms, "credential expiry")?;
        check(
            credential.issued_at_ms < credential.expires_at_ms
                && credential.expires_at_ms - credential.issued_at_ms <= MAX_GRANT_MS,
            "credential lifetime",
        )?;
        check(
            self.expires_at_ms == credential.expires_at_ms,
            "descriptor expiry",
        )?;
        check(
            credential.issued_at_ms <= self.issued_at_ms
                && self.issued_at_ms < credential.expires_at_ms,
            "descriptor issuance",
        )?;

        for (index, row) in self.subjects.iter().enumerate() {
            check(is_canonical_viz(&row.domain), "subject domain")?;
            check(is_lower_hex(&row.incarnation, 32), "subject incarnation")?;
            check(is_lower_hex(&row.nostr_pubkey, 64), "subject key")?;
            check(
                derive_subject_agent_id(&row.domain, &row.incarnation)? == row.subject_agent_id,
                "subject id",
            )?;
            check(
                self.subjects[..index].iter().all(|other| {
                    other.subject_agent_id != row.subject_agent_id
                        && other.nostr_pubkey != row.nostr_pubkey
                }),
                "duplicate subject",
            )?;
        }
        Ok(())
    }

    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.credential.scopes.iter().any(|s| s == scope)
    }

    pub(crate) fn is_live(&self, now_ms: u64) -> bool {
        self.credential.issued_at_ms <= now_ms && now_ms < self.expires_at_ms
    }

    /// The keyring account for this binding's secret.
    pub(crate) fn secret_key(&self) -> String {
        format!(
            "behavior-read:{}|{}|{}|{}|{}",
            self.owner_id,
            self.mailbox_id,
            self.principal_id,
            self.credential.credential_id,
            self.base_url
        )
    }
}

/// Parse and validate a descriptor (rejects unknown and duplicate keys).
pub(crate) fn parse_binding(bytes: &[u8]) -> Result<ReadBinding, String> {
    let binding: ReadBinding =
        serde_json::from_slice(bytes).map_err(|_| "invalid read binding".to_string())?;
    binding.validate()?;
    Ok(binding)
}

// ── Error bodies ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    code: String,
}

/// Map an error response to its frozen code, only when status and body agree.
pub(crate) fn read_error_code(status: u16, body: &[u8]) -> &'static str {
    let Ok(error) = serde_json::from_slice::<ErrorBody>(body) else {
        return "unexpected_response";
    };
    match (status, error.code.as_str()) {
        (400, "invalid_cursor") => "invalid_cursor",
        (400, "invalid_query") => "invalid_query",
        (401, "unauthenticated") => "unauthenticated",
        (403, "forbidden") => "forbidden",
        (404, "not_found") => "not_found",
        (409, "decision_fork") => "decision_fork",
        (503, "unavailable") => "unavailable",
        _ => "unexpected_response",
    }
}

#[cfg(test)]
#[path = "behavior_wire_tests.rs"]
mod tests;
