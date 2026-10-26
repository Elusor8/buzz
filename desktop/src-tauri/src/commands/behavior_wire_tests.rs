//! LOCAL ONLY: synthetic fixtures, no network, no real identities or tokens.

use super::*;
use serde_json::{json, Value};

const OWNER: &str = "fixture-owner";
const MAILBOX: &str = "00000000-0000-4000-8000-000000000001";
const VECTOR_SUBJECT: &str = "sub1_fEy55qhTRRiZ4aECHsSqtGmDL2D8XlsXB9RAe0Jk_uw";
const ZERO_INCARNATION: &str = "00000000000000000000000000000000";

fn sig() -> Value {
    json!({ "alg": "Ed25519", "key_id": "fixture-key", "value_base64url": "A".repeat(86) })
}

fn scope(subject: Option<&str>) -> Scope<'_> {
    Scope {
        owner_id: OWNER,
        mailbox_id: MAILBOX,
        subject_agent_id: subject,
    }
}

// ── Identifiers ─────────────────────────────────────────────────────────────

#[test]
fn subject_id_matches_the_frozen_derivation_vector() {
    assert_eq!(
        derive_subject_agent_id("example.viz", ZERO_INCARNATION).unwrap(),
        VECTOR_SUBJECT
    );
    assert!(is_subject_agent_id(VECTOR_SUBJECT));
}

#[test]
fn subject_id_changes_with_incarnation_and_rejects_bad_inputs() {
    let other = derive_subject_agent_id("example.viz", &"1".repeat(32)).unwrap();
    assert_ne!(other, VECTOR_SUBJECT);
    assert!(derive_subject_agent_id("Example.viz", ZERO_INCARNATION).is_err());
    assert!(derive_subject_agent_id("example.viz", &"A".repeat(32)).is_err());
    assert!(derive_subject_agent_id("example.viz", "0000").is_err());
}

#[test]
fn canonical_viz_names() {
    for ok in ["a.viz", "agent-1.viz", "bot.team.viz", "0abc.viz"] {
        assert!(is_canonical_viz(ok), "{ok}");
    }
    for bad in [
        "viz",
        ".viz",
        "-a.viz",
        "A.viz",
        "a.b.c.viz",
        "a_b.viz",
        "a.viz.",
        &format!("{}.viz", "a".repeat(21)),
    ] {
        assert!(!is_canonical_viz(bad), "{bad}");
    }
}

#[test]
fn uuid_v4_shape_is_exact() {
    assert!(is_uuid_v4(MAILBOX));
    assert!(!is_uuid_v4("00000000-0000-1000-8000-000000000001"));
    assert!(!is_uuid_v4("00000000-0000-4000-c000-000000000001"));
    assert!(!is_uuid_v4("00000000-0000-4000-8000-00000000000A"));
}

#[test]
fn origins_must_be_canonical_https() {
    assert!(is_canonical_https_origin("https://mbx.example.test"));
    assert!(is_canonical_https_origin("https://mbx.example.test:8443"));
    for bad in [
        "https://mbx.example.test/",
        "http://mbx.example.test",
        "https://MBX.example.test",
        "https://mbx.example.test:443",
        "https://mbx.example.test/v1",
        "https://mbx.example.test?x=1",
        "https://user@mbx.example.test",
        "mbx.example.test",
    ] {
        assert!(!is_canonical_https_origin(bad), "{bad}");
    }
}

#[test]
fn read_token_shape_is_exact() {
    let token = format!("mbr1_{}", "A".repeat(43));
    assert!(is_read_token(&token));
    assert!(!is_read_token(&"A".repeat(43)));
    assert!(!is_read_token(&format!("mbr1_{}", "A".repeat(42))));
    assert!(!is_read_token(&format!("mbr1_{}=", "A".repeat(42))));
    assert!(!is_read_token(&format!("mbr1_{}+", "A".repeat(42))));
}

// ── Read binding ────────────────────────────────────────────────────────────

fn binding_json() -> Value {
    json!({
        "schema_version": "1.0",
        "owner_id": OWNER,
        "principal_id": "fixture-principal",
        "mailbox_id": MAILBOX,
        "base_url": "https://mbx.example.test",
        "tls": { "trust_mode": "system", "owner_ca_pem": null },
        "credential": {
            "credential_id": "00000000-0000-4000-8000-000000000002",
            "scopes": ["standing:read", "audit:read", "notifications:read", "recovery:read"],
            "issued_at_ms": 1_000,
            "expires_at_ms": 1_000 + 86_400_000u64,
        },
        "subjects": [{
            "subject_agent_id": VECTOR_SUBJECT,
            "domain": "example.viz",
            "incarnation": ZERO_INCARNATION,
            "nostr_pubkey": "a".repeat(64),
        }],
        "issued_at_ms": 2_000,
        "expires_at_ms": 1_000 + 86_400_000u64,
    })
}

fn parse(value: &Value) -> Result<ReadBinding, String> {
    parse_binding(&serde_json::to_vec(value).unwrap())
}

#[test]
fn valid_binding_parses() {
    let binding = parse(&binding_json()).unwrap();
    assert!(binding.has_scope("audit:read"));
    assert!(binding.is_live(2_000));
    assert!(!binding.is_live(1_000 + 86_400_000));
    assert!(!binding.is_live(999));
}

#[test]
fn binding_rejects_unknown_missing_and_duplicate_keys() {
    let mut extra = binding_json();
    extra["extra"] = json!(1);
    assert!(parse(&extra).is_err());

    let mut missing = binding_json();
    missing.as_object_mut().unwrap().remove("principal_id");
    assert!(parse(&missing).is_err());

    let mut no_pem_key = binding_json();
    no_pem_key["tls"]
        .as_object_mut()
        .unwrap()
        .remove("owner_ca_pem");
    assert!(parse(&no_pem_key).is_err());

    let text = serde_json::to_string(&binding_json()).unwrap();
    let duplicated = text.replacen("\"owner_id\"", "\"owner_id\":\"x\",\"owner_id\"", 1);
    assert!(parse_binding(duplicated.as_bytes()).is_err());
}

#[test]
fn binding_rejects_bad_fields() {
    let cases: Vec<(&str, Value)> = vec![
        (
            "/tls",
            json!({ "trust_mode": "system", "owner_ca_pem": "pem" }),
        ),
        (
            "/tls",
            json!({ "trust_mode": "owner_ca", "owner_ca_pem": null }),
        ),
        (
            "/tls",
            json!({ "trust_mode": "owner_ca", "owner_ca_pem": "not a pem" }),
        ),
        (
            "/tls",
            json!({ "trust_mode": "insecure", "owner_ca_pem": null }),
        ),
        ("/base_url", json!("http://mbx.example.test")),
        ("/mailbox_id", json!("mailbox-1")),
        ("/schema_version", json!("1.1")),
        (
            "/credential/scopes",
            json!(["standing:read", "standing:read"]),
        ),
        ("/credential/scopes", json!(["standing:write"])),
        ("/credential/expires_at_ms", json!(1_000 + 86_400_001u64)),
        ("/expires_at_ms", json!(1_000 + 86_400_001u64)),
        ("/expires_at_ms", json!(5_000)),
        ("/issued_at_ms", json!(500)),
        ("/credential/issued_at_ms", json!(1.5)),
        (
            "/subjects/0/subject_agent_id",
            json!(format!("sub1_{}", "A".repeat(43))),
        ),
        (
            "/subjects/0/nostr_pubkey",
            json!(format!("npub{}", "a".repeat(60))),
        ),
        ("/subjects/0/incarnation", json!("0".repeat(31))),
    ];
    for (pointer, value) in cases {
        let mut bad = binding_json();
        *bad.pointer_mut(pointer).unwrap() = value.clone();
        assert!(parse(&bad).is_err(), "{pointer} = {value}");
    }
}

#[test]
fn binding_rejects_duplicate_subject_keys() {
    let mut bad = binding_json();
    let row = bad["subjects"][0].clone();
    let mut second = row.clone();
    second["incarnation"] = json!("1".repeat(32));
    second["subject_agent_id"] =
        json!(derive_subject_agent_id("example.viz", &"1".repeat(32)).unwrap());
    bad["subjects"] = json!([row, second]);
    assert!(parse(&bad).is_err(), "same Nostr key on two rows");
}

// ── Standing ────────────────────────────────────────────────────────────────

/// The frozen synthetic no-measurement example, verbatim.
fn no_measurement() -> Value {
    json!({
        "schema_version": "1.0",
        "as_of_ms": 0,
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": VECTOR_SUBJECT,
        "identity_validity": "unverified",
        "standing": "unknown",
        "decision_ref": null,
        "evidence_version": null,
        "window": null,
        "policy_version": null,
        "effective_allowance": {
            "max_turns_per_conversation": 0,
            "max_new_conversations_per_hour": 0,
            "max_actions_per_hour": 0,
            "permitted_action_classes": [],
            "rate_limit_per_hour": 0
        },
        "executable": false,
        "checked_at_ms": 0,
        "fresh_until_ms": null,
        "verification_status": "not_measured",
        "reason_code": "fail_closed"
    })
}

fn verified(standing: &str) -> Value {
    json!({
        "schema_version": "1.0",
        "as_of_ms": 10_000,
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": VECTOR_SUBJECT,
        "identity_validity": "valid",
        "standing": standing,
        "decision_ref": { "id": "fixture-decision-7", "basis": "current", "digest_sha256": "b".repeat(64) },
        "evidence_version": 3,
        "window": { "start_ms": 1_000, "end_ms": 9_000 },
        "policy_version": 2,
        "effective_allowance": {
            "max_turns_per_conversation": 4,
            "max_new_conversations_per_hour": 1,
            "max_actions_per_hour": 4,
            "permitted_action_classes": ["conversation.turn"],
            "rate_limit_per_hour": 10
        },
        "executable": true,
        "checked_at_ms": 9_500,
        "fresh_until_ms": 70_000,
        "verification_status": "verified",
        "reason_code": null
    })
}

fn standing(value: &Value) -> Result<StandingRead, String> {
    let read: StandingRead = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    read.validate(OWNER, MAILBOX, VECTOR_SUBJECT)?;
    Ok(read)
}

fn zero_allowance(value: &mut Value) {
    value["effective_allowance"] = no_measurement()["effective_allowance"].clone();
}

#[test]
fn frozen_example_is_accepted_and_not_current() {
    let read = standing(&no_measurement()).unwrap();
    assert_eq!(read.standing, Standing::Unknown);
    assert!(!read.is_current(0));
}

#[test]
fn verified_standing_is_current_until_fresh_until() {
    let read = standing(&verified("reduced")).unwrap();
    assert!(read.is_current(69_999));
    assert!(!read.is_current(70_000));
}

#[test]
fn standing_rejects_missing_unknown_and_mistyped_fields() {
    let mut missing = verified("normal");
    missing.as_object_mut().unwrap().remove("reason_code");
    assert!(standing(&missing).is_err(), "nullable key still required");

    let mut extra = verified("normal");
    extra["score"] = json!(0.5);
    assert!(standing(&extra).is_err());

    for (key, value) in [
        ("as_of_ms", json!(1.0)),
        ("as_of_ms", json!("10000")),
        ("as_of_ms", json!(-1)),
        ("as_of_ms", json!(9_007_199_254_740_992u64)),
        ("standing", json!("bad")),
        ("verification_status", json!("ok")),
        ("schema_version", json!("2.0")),
    ] {
        let mut bad = verified("normal");
        bad[key] = value.clone();
        assert!(standing(&bad).is_err(), "{key} = {value}");
    }
}

#[test]
fn standing_rejects_another_partition() {
    let mut other = verified("normal");
    other["owner_id"] = json!("other-owner");
    assert!(standing(&other).is_err());
    let read: StandingRead = serde_json::from_value(verified("normal")).unwrap();
    assert!(read.validate(OWNER, MAILBOX, "sub1_other").is_err());
}

#[test]
fn unverified_snapshot_must_be_fail_closed() {
    let mut open = verified("normal");
    open["verification_status"] = json!("stale");
    open["decision_ref"]["basis"] = json!("last_known");
    assert!(standing(&open).is_err(), "executable while unverified");

    zero_allowance(&mut open);
    open["executable"] = json!(false);
    open["fresh_until_ms"] = Value::Null;
    open["reason_code"] = json!("fail_closed");
    let read = standing(&open).unwrap();
    // Last-known normal stays normal, but nothing is executable.
    assert_eq!(read.standing, Standing::Normal);
    assert!(!read.executable);
    assert!(!read.is_current(10_000));

    let mut current_basis = open.clone();
    current_basis["decision_ref"]["basis"] = json!("current");
    assert!(standing(&current_basis).is_err());
}

#[test]
fn verified_requires_valid_identity_current_basis_and_freshness() {
    let mut invalid_identity = verified("normal");
    invalid_identity["identity_validity"] = json!("invalid");
    assert!(standing(&invalid_identity).is_err());

    let mut last_known = verified("normal");
    last_known["decision_ref"]["basis"] = json!("last_known");
    assert!(standing(&last_known).is_err());

    let mut with_reason = verified("normal");
    with_reason["reason_code"] = json!("fail_closed");
    assert!(standing(&with_reason).is_err());

    let mut stale_window = verified("normal");
    stale_window["fresh_until_ms"] = json!(10_000);
    assert!(standing(&stale_window).is_err());

    let mut no_decision = verified("normal");
    no_decision["decision_ref"] = Value::Null;
    assert!(standing(&no_decision).is_err());
}

#[test]
fn denied_is_never_executable() {
    assert!(standing(&verified("denied")).is_err());
    let mut denied = verified("denied");
    zero_allowance(&mut denied);
    denied["executable"] = json!(false);
    assert_eq!(standing(&denied).unwrap().standing, Standing::Denied);
}

#[test]
fn absent_decision_means_unknown_with_null_provenance() {
    let mut relabeled = no_measurement();
    relabeled["standing"] = json!("denied");
    assert!(
        standing(&relabeled).is_err(),
        "no decision cannot be denied"
    );

    let mut stray = no_measurement();
    stray["evidence_version"] = json!(1);
    assert!(standing(&stray).is_err());
}

#[test]
fn decision_window_and_versions_are_checked() {
    let mut window = verified("normal");
    window["window"] = json!({ "start_ms": 9_000, "end_ms": 9_000 });
    assert!(standing(&window).is_err());
    let mut version = verified("normal");
    version["policy_version"] = json!(0);
    assert!(standing(&version).is_err());
    let mut digest = verified("normal");
    digest["decision_ref"]["digest_sha256"] = json!("B".repeat(64));
    assert!(standing(&digest).is_err());
}

#[test]
fn calibrating_is_its_own_state() {
    let mut calibrating = verified("calibrating");
    zero_allowance(&mut calibrating);
    calibrating["executable"] = json!(false);
    assert_eq!(
        standing(&calibrating).unwrap().standing,
        Standing::Calibrating
    );
}

// ── Lists ───────────────────────────────────────────────────────────────────

fn denied_attempt(time: u64, attempt: &str) -> Value {
    json!({
        "schema_version": "1.0",
        "type": "mailbox.denied_attempt",
        "id": format!("fixture-da-{attempt}"),
        "issued_at_ms": time,
        "signature": sig(),
        "attempt_id": attempt,
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": VECTOR_SUBJECT,
        "decision_id": "fixture-decision-7",
        "policy_version": 2,
        "attempted_action_class": "conversation.open",
        "timestamp_ms": time,
        "reason_code": "new_conversation_allowance_exhausted",
        "outcome": "denied",
        "receipt_id": format!("fixture-receipt-{attempt}"),
    })
}

fn notification(state: &str) -> Value {
    json!({
        "notification_id": "fixture-n-1",
        "episode_id": "fixture-e-1",
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": VECTOR_SUBJECT,
        "decision_id": "fixture-decision-7",
        "standing": "reduced",
        "reason_codes": ["behavior_shift"],
        "evidence_version": 3,
        "window": { "start_ms": 1_000, "end_ms": 9_000 },
        "policy_version": 2,
        "created_at_ms": 9_600,
        "delivery_state": state,
        "attempt_count": 1,
    })
}

fn receipt(result: &str, reason: &str) -> Value {
    json!({
        "schema_version": "1.0",
        "type": "mailbox.restoration_receipt",
        "id": "fixture-rr-1",
        "recovery_authorization_id": "fixture-ra-1",
        "previous_decision_id": "fixture-decision-7",
        "new_decision_id": "fixture-decision-8",
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": VECTOR_SUBJECT,
        "policy_version": 2,
        "evidence_version": 4,
        "window": { "start_ms": 9_000, "end_ms": 19_000 },
        "restored_allowance_digest": "c".repeat(64),
        "effective_at_ms": 20_000,
        "authorization_digest": "d".repeat(64),
        "result": result,
        "reason_code": reason,
        "issued_at_ms": 20_001,
        "signature": sig(),
    })
}

fn envelope(subject: Option<&str>, items: Vec<Value>, cursor: Option<&str>) -> Value {
    json!({
        "schema_version": "1.0",
        "as_of_ms": 30_000,
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": subject,
        "items": items,
        "next_cursor": cursor,
    })
}

fn page<T: ListRecord + serde::de::DeserializeOwned>(
    value: &Value,
    subject: Option<&str>,
    previous: Option<(u64, (u64, &str))>,
) -> Result<ListPage<T>, String> {
    let page: ListPage<T> = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    page.validate(&scope(subject), previous)?;
    Ok(page)
}

#[test]
fn frozen_empty_notifications_snapshot_is_accepted() {
    let value = json!({
        "schema_version": "1.0",
        "as_of_ms": 0,
        "owner_id": OWNER,
        "mailbox_id": MAILBOX,
        "subject_agent_id": null,
        "items": [],
        "next_cursor": null
    });
    assert!(page::<OwnerNotification>(&value, None, None).is_ok());
    let mut keyed = value.clone();
    keyed.as_object_mut().unwrap().remove("next_cursor");
    assert!(page::<OwnerNotification>(&keyed, None, None).is_err());
}

#[test]
fn list_envelope_rules() {
    let s = Some(VECTOR_SUBJECT);
    assert!(page::<DeniedAttempt>(&envelope(s, vec![], Some("abc")), s, None).is_err());
    assert!(page::<DeniedAttempt>(&envelope(None, vec![], None), s, None).is_err());
    assert!(page::<OwnerNotification>(&envelope(s, vec![], None), None, None).is_err());
    let items = vec![denied_attempt(5, "a1"), denied_attempt(6, "a2")];
    assert!(page::<DeniedAttempt>(&envelope(s, items, Some("Y3Vyc29y")), s, None).is_ok());
    let bad_cursor = envelope(s, vec![denied_attempt(5, "a1")], Some("not base64!"));
    assert!(page::<DeniedAttempt>(&bad_cursor, s, None).is_err());
}

#[test]
fn list_order_and_snapshot_are_enforced() {
    let s = Some(VECTOR_SUBJECT);
    let reversed = envelope(
        s,
        vec![denied_attempt(6, "a2"), denied_attempt(5, "a1")],
        None,
    );
    assert!(page::<DeniedAttempt>(&reversed, s, None).is_err());
    let tie = envelope(
        s,
        vec![denied_attempt(5, "a1"), denied_attempt(5, "a0")],
        None,
    );
    assert!(page::<DeniedAttempt>(&tie, s, None).is_err());

    let next = envelope(s, vec![denied_attempt(7, "a3")], None);
    assert!(page::<DeniedAttempt>(&next, s, Some((30_000, (6, "a2")))).is_ok());
    assert!(page::<DeniedAttempt>(&next, s, Some((29_999, (6, "a2")))).is_err());
    assert!(page::<DeniedAttempt>(&next, s, Some((30_000, (8, "a4")))).is_err());
}

#[test]
fn denied_attempt_record_rules() {
    let s = Some(VECTOR_SUBJECT);
    let check = |item: Value| page::<DeniedAttempt>(&envelope(s, vec![item], None), s, None);
    assert!(check(denied_attempt(5, "a1")).is_ok());

    let mut with_conversation = denied_attempt(5, "a1");
    with_conversation["conversation_id"] = json!("fixture-conv");
    assert!(check(with_conversation).is_ok());

    let mut null_conversation = denied_attempt(5, "a1");
    null_conversation["conversation_id"] = Value::Null;
    assert!(check(null_conversation).is_err(), "absent, never null");

    for (key, value) in [
        ("reason_code", json!("allowed")),
        ("type", json!("mailbox.denied")),
        ("outcome", json!("allowed")),
        ("owner_id", json!("other-owner")),
        (
            "subject_agent_id",
            json!(format!("sub1_{}", "B".repeat(43))),
        ),
        ("attempted_action_class", json!("Send Email")),
        ("message", json!("content")),
    ] {
        let mut bad = denied_attempt(5, "a1");
        bad[key] = value.clone();
        assert!(check(bad).is_err(), "{key} = {value}");
    }

    let mut bad_sig = denied_attempt(5, "a1");
    bad_sig["signature"]["alg"] = json!("ES256");
    assert!(check(bad_sig).is_err());
}

#[test]
fn notification_delivery_is_never_inferred() {
    let check =
        |item: Value| page::<OwnerNotification>(&envelope(None, vec![item], None), None, None);
    assert!(check(notification("queued")).is_ok());

    let mut queued_with_time = notification("queued");
    queued_with_time["delivered_at_ms"] = json!(9_700);
    assert!(check(queued_with_time).is_err());

    assert!(
        check(notification("delivered")).is_err(),
        "delivered needs a time"
    );
    let mut delivered = notification("delivered");
    delivered["delivered_at_ms"] = json!(9_700);
    assert!(check(delivered).is_ok());

    assert!(
        check(notification("failed")).is_err(),
        "failed needs a code"
    );
    let mut failed = notification("failed");
    failed["failure_code"] = json!("http_404");
    assert!(check(failed.clone()).is_ok());
    failed["failure_code"] = json!("http_200");
    assert!(check(failed.clone()).is_err());
    failed["failure_code"] = json!("connection refused by host");
    assert!(check(failed).is_err());

    let mut retrying = notification("retrying");
    retrying["failure_code"] = json!("timeout");
    retrying["last_attempt_at_ms"] = json!(9_650);
    assert!(check(retrying).is_ok());
}

#[test]
fn notification_provenance_and_reasons() {
    let check =
        |item: Value| page::<OwnerNotification>(&envelope(None, vec![item], None), None, None);

    let mut fail_closed = notification("queued");
    fail_closed["standing"] = json!("unknown");
    fail_closed["reason_codes"] = json!(["state_unverifiable", "fail_closed"]);
    fail_closed["decision_id"] = Value::Null;
    fail_closed["evidence_version"] = Value::Null;
    fail_closed["window"] = Value::Null;
    fail_closed["policy_version"] = Value::Null;
    assert!(check(fail_closed.clone()).is_ok());

    let mut half = fail_closed.clone();
    half["evidence_version"] = json!(3);
    assert!(check(half).is_err(), "window and evidence travel together");

    let mut ordinary_null = notification("queued");
    ordinary_null["decision_id"] = Value::Null;
    assert!(check(ordinary_null).is_err());

    for (standing, reasons, ok) in [
        ("reduced", json!(["behavior_shift"]), true),
        ("reduced", json!([]), false),
        ("reduced", json!(["owner_revoked"]), false),
        ("denied", json!(["owner_revoked"]), true),
        (
            "denied",
            json!(["behavior_shift", "recovery_authorized"]),
            false,
        ),
        ("normal", json!([]), true),
        ("normal", json!(["recovery_authorized"]), true),
        ("normal", json!(["behavior_shift"]), false),
        ("calibrating", json!(["calibration_incomplete"]), true),
        ("unknown", json!(["stale"]), true),
        ("unknown", json!(["behavior_shift"]), false),
        ("notify", json!(["behavior_shift", "behavior_shift"]), false),
    ] {
        let mut item = notification("queued");
        item["standing"] = json!(standing);
        item["reason_codes"] = reasons.clone();
        assert_eq!(check(item).is_ok(), ok, "{standing} {reasons}");
    }
}

#[test]
fn restoration_receipt_rules() {
    let s = Some(VECTOR_SUBJECT);
    let check = |item: Value| page::<RestorationReceipt>(&envelope(s, vec![item], None), s, None);
    assert!(check(receipt("restored", "restored")).is_ok());
    assert!(check(receipt("refused", "expired")).is_ok());
    assert!(check(receipt("restored", "expired")).is_err());
    assert!(check(receipt("refused", "restored")).is_err());
    assert!(check(receipt("refused", "recovery_authorized")).is_err());
    let mut wrong_type = receipt("restored", "restored");
    wrong_type["type"] = json!("mailbox.recovery_authorization");
    assert!(
        check(wrong_type).is_err(),
        "a receipt is not an authorization"
    );
}

#[test]
fn error_bodies_map_only_when_status_agrees() {
    assert_eq!(
        read_error_code(401, br#"{"code":"unauthenticated"}"#),
        "unauthenticated"
    );
    assert_eq!(
        read_error_code(403, br#"{"code":"forbidden"}"#),
        "forbidden"
    );
    assert_eq!(
        read_error_code(404, br#"{"code":"not_found"}"#),
        "not_found"
    );
    assert_eq!(
        read_error_code(409, br#"{"code":"decision_fork"}"#),
        "decision_fork"
    );
    assert_eq!(
        read_error_code(503, br#"{"code":"unavailable"}"#),
        "unavailable"
    );
    assert_eq!(
        read_error_code(400, br#"{"code":"invalid_cursor"}"#),
        "invalid_cursor"
    );
    assert_eq!(
        read_error_code(400, br#"{"code":"invalid_query"}"#),
        "invalid_query"
    );
    assert_eq!(
        read_error_code(401, br#"{"code":"forbidden"}"#),
        "unexpected_response"
    );
    assert_eq!(
        read_error_code(503, br#"{"code":"unavailable","detail":"x"}"#),
        "unexpected_response"
    );
    assert_eq!(read_error_code(500, b"oops"), "unexpected_response");
}
