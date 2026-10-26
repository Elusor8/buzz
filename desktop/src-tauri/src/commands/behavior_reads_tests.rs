//! LOCAL ONLY: synthetic fixtures, no network, no real identities or tokens.

use super::*;
use crate::commands::behavior_wire::{derive_subject_agent_id, parse_binding};

const DOMAIN: &str = "example.viz";
const INCARNATION: &str = "00000000000000000000000000000000";

fn key() -> String {
    "a".repeat(64)
}

fn binding() -> ReadBinding {
    let value = serde_json::json!({
        "schema_version": "1.0",
        "owner_id": "fixture-owner",
        "principal_id": "fixture-principal",
        "mailbox_id": "00000000-0000-4000-8000-000000000001",
        "base_url": "https://mbx.example.test",
        "tls": { "trust_mode": "system", "owner_ca_pem": null },
        "credential": {
            "credential_id": "00000000-0000-4000-8000-000000000002",
            "scopes": ["standing:read"],
            "issued_at_ms": 1_000,
            "expires_at_ms": 2_000,
        },
        "subjects": [{
            "subject_agent_id": derive_subject_agent_id(DOMAIN, INCARNATION).unwrap(),
            "domain": DOMAIN,
            "incarnation": INCARNATION,
            "nostr_pubkey": key(),
        }],
        "issued_at_ms": 1_000,
        "expires_at_ms": 2_000,
    });
    parse_binding(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn verified(identity: &str, pubkey: &str, incarnation: Option<&str>) -> VerifyOutcome {
    VerifyOutcome::Verified {
        identity: identity.into(),
        verifier: "verifier.viz".into(),
        nostr_pubkey: pubkey.into(),
        event_id: "e".repeat(64),
        proof_id: None,
        incarnation: incarnation.map(str::to_string),
        checked_at: 0,
        reputation: None,
        blue_tick: None,
    }
}

#[test]
fn exact_identity_matches_its_provisioned_subject() {
    let matched = match_subject(&binding(), &verified(DOMAIN, &key(), Some(INCARNATION)));
    let SubjectMatch::Matched {
        domain,
        subject_agent_id,
    } = matched
    else {
        panic!("expected a match, got {matched:?}");
    };
    assert_eq!(domain, DOMAIN);
    assert_eq!(
        subject_agent_id,
        "sub1_fEy55qhTRRiZ4aECHsSqtGmDL2D8XlsXB9RAe0Jk_uw"
    );
}

#[test]
fn nothing_is_attributed_without_an_exact_match() {
    let b = binding();
    let cases = [
        (
            VerifyOutcome::Rejected {
                code: "E_PROOF_EXPIRED".into(),
            },
            "identity_not_verified",
        ),
        (
            VerifyOutcome::Unavailable {
                code: "E_REGISTRY_UNREACHABLE".into(),
            },
            "identity_not_verified",
        ),
        (verified(DOMAIN, &key(), None), "no_incarnation"),
        (
            verified(DOMAIN, &"b".repeat(64), Some(INCARNATION)),
            "not_provisioned",
        ),
        (verified("other.viz", &key(), Some(INCARNATION)), "mismatch"),
        (verified(DOMAIN, &key(), Some(&"1".repeat(32))), "mismatch"),
    ];
    for (outcome, expected) in cases {
        let result = serde_json::to_value(match_subject(&b, &outcome)).unwrap();
        assert_eq!(result["status"], expected, "{outcome:?}");
    }
}

#[test]
fn binding_status_reports_expiry_before_touching_secure_storage() {
    let stored = StoredBinding::Present(Box::new(binding()));
    let status = serde_json::to_value(status_of(&stored, 2_000)).unwrap();
    assert_eq!(status["state"], "expired");
    let none = serde_json::to_value(status_of(&StoredBinding::None, 0)).unwrap();
    assert_eq!(none["state"], "none");
    let invalid = serde_json::to_value(status_of(&StoredBinding::Invalid, 0)).unwrap();
    assert_eq!(invalid["state"], "invalid");
}

#[test]
fn read_paths_use_only_the_frozen_routes() {
    let b = binding();
    let subject = derive_subject_agent_id(DOMAIN, INCARNATION).unwrap();
    assert_eq!(
        peer_path(&b, &subject, "standing"),
        format!("/v1/mailboxes/00000000-0000-4000-8000-000000000001/peers/{subject}/standing")
    );
}

#[test]
fn owner_ca_binding_builds_a_pinned_client() {
    let mut b = binding();
    assert!(client_for(&b).is_ok());
    b.tls.trust_mode = TrustMode::OwnerCa;
    b.tls.owner_ca_pem = None;
    assert!(client_for(&b).is_err());
}
