//! The owner-provisioned read binding descriptor (non-secret configuration).

use serde::{Deserialize, Serialize};

use super::{
    check, derive_subject_agent_id, is_canonical_https_origin, is_canonical_viz, is_lower_hex,
    is_opaque_id, is_uuid_v4, required_nullable, uint, unique, MAX_GRANT_MS, SCHEMA_VERSION,
    SCOPES,
};

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
