//! Local-only tests: synthetic keys generated per test, no network.

use super::*;

const NOW: u64 = 1_800_000_000;

struct Fixture {
    verifier_keys: Keys,
    prover_keys: Keys,
    request: VerifyRequest,
}

fn fixture() -> Fixture {
    let verifier_keys = Keys::generate();
    let prover_keys = Keys::generate();
    let request = VerifyRequest {
        verifier: "alpha.viz".into(),
        verifier_pubkey: verifier_keys.public_key().to_hex(),
        prover: "bravo.viz".into(),
        prover_pubkey: prover_keys.public_key().to_hex(),
        nonce: "00112233445566778899aabbccddeeff".into(),
    };
    Fixture {
        verifier_keys,
        prover_keys,
        request,
    }
}

fn proof(fx: &Fixture) -> Event {
    build_proof_event(&fx.prover_keys, &fx.request, NOW).expect("proof")
}

const INCARNATION: &str = "0123456789abcdef0123456789abcdef";

fn verified_body(fx: &Fixture, event: &Event) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "verified": true,
        "identity": fx.request.prover,
        "scheme": "nostr",
        "nostr_pubkey": event.pubkey.to_hex(),
        "event_id": event.id.to_hex(),
        "kind": 30388,
        "freshness_checked": true,
        "owner_attestation": null,
        "link": { "proof_id": "p1", "incarnation": INCARNATION, "revision": 1 },
        "reputation": {
            "entropy_score": 0.42,
            "drift_detected": false,
            "z_score": 1.1,
            "calibration_stage": "calibrated",
        },
        "blue_tick": true,
    }))
    .unwrap()
}

// ── Formats ─────────────────────────────────────────────────────────────────

#[test]
fn request_round_trips_through_message_content() {
    let fx = fixture();
    let content = format_request(&fx.request).unwrap();
    assert!(content.starts_with(REQUEST_MARKER));
    assert_eq!(parse_request(&content).unwrap(), fx.request);
}

#[test]
fn request_rejects_unknown_fields_and_bad_values() {
    let fx = fixture();
    let mut json: serde_json::Value = serde_json::to_value(&fx.request).unwrap();
    json["extra"] = "x".into();
    assert!(parse_request(&format!("{REQUEST_MARKER}\n{json}")).is_err());

    for (field, value) in [
        ("prover", "Bravo.viz"),
        ("prover", "bravo.com"),
        ("prover_pubkey", "ABCD"),
        ("nonce", "short"),
    ] {
        let mut json: serde_json::Value = serde_json::to_value(&fx.request).unwrap();
        json[field] = value.into();
        assert!(
            parse_request(&format!("{REQUEST_MARKER}\n{json}")).is_err(),
            "{field}={value} should be refused"
        );
    }
}

#[test]
fn request_refuses_self_verification() {
    let mut fx = fixture();
    fx.request.prover_pubkey = fx.request.verifier_pubkey.clone();
    assert!(format_request(&fx.request).is_err());
}

#[test]
fn plain_text_is_not_a_request_or_proof() {
    assert!(parse_request("hello").is_err());
    assert!(parse_proof("hello").is_err());
}

#[test]
fn viz_domain_shape_matches_registry() {
    for ok in [
        "a.viz",
        "relay-bot.demo.viz",
        "a1.b2.viz",
        "abcdefghijklmnopqrst.viz",
    ] {
        assert!(is_viz_domain(ok), "{ok}");
    }
    for bad in [
        ".viz",
        "viz",
        "-a.viz",
        "A.viz",
        "a.b.c.viz",
        "abcdefghijklmnopqrstu.viz",
        "a_b.viz",
        "a.viz.",
    ] {
        assert!(!is_viz_domain(bad), "{bad}");
    }
}

// ── Proof construction and key custody ──────────────────────────────────────

#[test]
fn proof_is_kind_30388_with_fixed_content_and_tags() {
    let fx = fixture();
    let event = proof(&fx);
    assert_eq!(event.kind, Kind::Custom(30388));
    assert_eq!(
        event.content,
        "zipviz:agent-verify:v1:bravo.viz:alpha.viz:00112233445566778899aabbccddeeff"
    );
    let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    assert_eq!(tags, proof_tags(&fx.request));
    assert_eq!(event.pubkey, fx.prover_keys.public_key());
}

#[test]
fn proof_json_has_exactly_the_seven_nip01_keys() {
    let fx = fixture();
    let value: serde_json::Value = serde_json::from_str(&proof(&fx).as_json()).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "content",
            "created_at",
            "id",
            "kind",
            "pubkey",
            "sig",
            "tags"
        ]
    );
}

#[test]
fn proof_refuses_any_key_but_the_requested_prover() {
    let fx = fixture();
    assert!(build_proof_event(&fx.verifier_keys, &fx.request, NOW).is_err());
    assert!(build_proof_event(&Keys::generate(), &fx.request, NOW).is_err());
}

#[test]
fn proof_never_resembles_registry_consent() {
    let fx = fixture();
    let event = proof(&fx);
    assert!(!event.content.starts_with("zipviz:identity-link"));
    assert!(!event.tags.iter().any(|t| t
        .as_slice()
        .get(1)
        .is_some_and(|v| v == "zipviz:identity-link:v2")));
}

#[test]
fn proof_message_never_contains_secret_key_material() {
    let fx = fixture();
    let content = format_proof(&proof(&fx));
    let secret_hex = fx.prover_keys.secret_key().to_secret_hex();
    assert!(!content.contains(&secret_hex));
    assert!(!content.contains("nsec1"));
    assert!(!content.contains("ncryptsec1"));
}

#[test]
fn proof_round_trips_through_message_content() {
    let fx = fixture();
    let event = proof(&fx);
    assert_eq!(parse_proof(&format_proof(&event)).unwrap(), event);
}

// ── Local binding checks ────────────────────────────────────────────────────

#[test]
fn genuine_proof_passes_binding() {
    let fx = fixture();
    assert_eq!(check_binding(&proof(&fx), &fx.request, NOW), Ok(()));
    assert_eq!(
        check_binding(&proof(&fx), &fx.request, NOW + FRESHNESS_SECS),
        Ok(())
    );
}

#[test]
fn tampered_content_is_rejected() {
    let fx = fixture();
    let json = proof(&fx).as_json().replace("bravo.viz", "brava.viz");
    let event = Event::from_json(json).unwrap();
    assert_eq!(
        check_binding(&event, &fx.request, NOW),
        Err("E_PROOF_ID_MISMATCH")
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let fx = fixture();
    let event = proof(&fx);
    let mut value: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
    let sig = value["sig"].as_str().unwrap().to_string();
    let flipped = if sig.starts_with('0') { "1" } else { "0" };
    value["sig"] = format!("{flipped}{}", &sig[1..]).into();
    let event = Event::from_json(value.to_string()).unwrap();
    assert_eq!(
        check_binding(&event, &fx.request, NOW),
        Err("E_PROOF_SIG_INVALID")
    );
}

#[test]
fn proof_from_another_agent_is_rejected() {
    let fx = fixture();
    let mut imposter_request = fx.request.clone();
    let imposter = Keys::generate();
    imposter_request.prover_pubkey = imposter.public_key().to_hex();
    let event = build_proof_event(&imposter, &imposter_request, NOW).unwrap();
    assert_eq!(
        check_binding(&event, &fx.request, NOW),
        Err("E_PROOF_WRONG_SIGNER")
    );
}

#[test]
fn proof_replayed_to_another_request_is_rejected() {
    let fx = fixture();
    let event = proof(&fx);
    let mut other = fx.request.clone();
    other.nonce = "ffeeddccbbaa99887766554433221100".into();
    assert_eq!(
        check_binding(&event, &other, NOW),
        Err("E_PROOF_NOT_FOR_REQUEST")
    );
    let mut other_verifier = fx.request.clone();
    other_verifier.verifier = "charlie.viz".into();
    assert_eq!(
        check_binding(&event, &other_verifier, NOW),
        Err("E_PROOF_NOT_FOR_REQUEST")
    );
}

#[test]
fn stale_or_future_proof_is_rejected() {
    let fx = fixture();
    let event = proof(&fx);
    assert_eq!(
        check_binding(&event, &fx.request, NOW + FRESHNESS_SECS + 1),
        Err("E_PROOF_EXPIRED")
    );
    assert_eq!(
        check_binding(&event, &fx.request, NOW - FRESHNESS_SECS - 1),
        Err("E_PROOF_EXPIRED")
    );
}

#[test]
fn extra_tag_is_rejected() {
    let fx = fixture();
    let tags = proof_tags(&fx.request)
        .into_iter()
        .chain([vec!["t".to_string(), "x".to_string()]])
        .map(|t| Tag::parse(t).unwrap())
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::Custom(PROOF_KIND), proof_content(&fx.request))
        .tags(tags)
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&fx.prover_keys)
        .unwrap();
    assert_eq!(
        check_binding(&event, &fx.request, NOW),
        Err("E_PROOF_NOT_FOR_REQUEST")
    );
}

// ── Registry response interpretation ────────────────────────────────────────

#[test]
fn exact_registry_success_is_verified() {
    let fx = fixture();
    let event = proof(&fx);
    let outcome =
        interpret_registry_response(200, &verified_body(&fx, &event), &fx.request, &event, NOW);
    assert_eq!(
        outcome,
        VerifyOutcome::Verified {
            identity: "bravo.viz".into(),
            verifier: "alpha.viz".into(),
            nostr_pubkey: fx.request.prover_pubkey.clone(),
            event_id: event.id.to_hex(),
            proof_id: Some("p1".into()),
            incarnation: Some(INCARNATION.into()),
            checked_at: NOW,
            reputation: Some(Reputation {
                entropy_score: Some(0.42),
                drift_detected: Some(false),
                z_score: Some(1.1),
                calibration_stage: Some("calibrated".into()),
            }),
            blue_tick: Some(true),
        }
    );
}

#[test]
fn registry_incarnation_must_be_exact_lower_hex32() {
    let fx = fixture();
    let event = proof(&fx);
    for bad in [
        serde_json::json!("i1"),
        serde_json::json!("0123456789ABCDEF0123456789ABCDEF"),
        serde_json::json!(7),
        serde_json::Value::Null,
    ] {
        let mut body: serde_json::Value =
            serde_json::from_slice(&verified_body(&fx, &event)).unwrap();
        body["link"]["incarnation"] = bad;
        let outcome = interpret_registry_response(
            200,
            &serde_json::to_vec(&body).unwrap(),
            &fx.request,
            &event,
            NOW,
        );
        assert!(matches!(
            outcome,
            VerifyOutcome::Verified {
                incarnation: None,
                ..
            }
        ));
    }
}

#[test]
fn registry_behavior_reading_is_passed_through_strictly() {
    let fx = fixture();
    let event = proof(&fx);
    let outcome_with = |reputation: serde_json::Value, blue_tick: serde_json::Value| {
        let mut body: serde_json::Value =
            serde_json::from_slice(&verified_body(&fx, &event)).unwrap();
        body["reputation"] = reputation;
        body["blue_tick"] = blue_tick;
        interpret_registry_response(
            200,
            &serde_json::to_vec(&body).unwrap(),
            &fx.request,
            &event,
            NOW,
        )
    };
    let trust = |outcome: VerifyOutcome| match outcome {
        VerifyOutcome::Verified {
            reputation,
            blue_tick,
            ..
        } => (reputation, blue_tick),
        other => panic!("identity must stay verified: {other:?}"),
    };

    // Unavailable behavior never breaks a valid identity, and is not trust.
    assert_eq!(
        trust(outcome_with(
            serde_json::Value::Null,
            serde_json::Value::Null
        )),
        (None, None)
    );
    // Drift is reported as the registry measured it.
    let (reputation, blue_tick) = trust(outcome_with(
        serde_json::json!({"entropy_score": 3.0, "drift_detected": true, "z_score": 4.2, "calibration_stage": "full"}),
        serde_json::json!(false),
    ));
    assert_eq!(reputation.unwrap().drift_detected, Some(true));
    assert_eq!(blue_tick, Some(false));
    // Unexpected shapes are dropped, never shown as a reading.
    for bad in [
        serde_json::json!({"drift_detected": "no"}),
        serde_json::json!({"calibration_stage": "excellent"}),
        serde_json::json!({"z_score": "1"}),
        serde_json::json!({"extra": 1}),
        serde_json::json!([1]),
    ] {
        assert_eq!(
            trust(outcome_with(bad, serde_json::json!("yes"))),
            (None, None)
        );
    }
}

#[test]
fn verified_false_with_http_200_is_rejected() {
    let fx = fixture();
    let event = proof(&fx);
    let body = br#"{"verified":false,"error":"signature mismatch","code":"E_NOSTR_SIG_INVALID"}"#;
    assert_eq!(
        interpret_registry_response(200, body, &fx.request, &event, NOW),
        VerifyOutcome::Rejected {
            code: "E_NOSTR_SIG_INVALID".into()
        }
    );
}

#[test]
fn success_for_another_identity_or_event_is_rejected() {
    let fx = fixture();
    let event = proof(&fx);
    for (key, value) in [
        ("identity", serde_json::json!("charlie.viz")),
        (
            "nostr_pubkey",
            serde_json::json!(fx.request.verifier_pubkey),
        ),
        ("event_id", serde_json::json!("00".repeat(32))),
        ("kind", serde_json::json!(1)),
        ("verified", serde_json::json!("true")),
    ] {
        let mut body: serde_json::Value =
            serde_json::from_slice(&verified_body(&fx, &event)).unwrap();
        body[key] = value;
        let outcome = interpret_registry_response(
            200,
            &serde_json::to_vec(&body).unwrap(),
            &fx.request,
            &event,
            NOW,
        );
        assert!(
            matches!(outcome, VerifyOutcome::Rejected { .. }),
            "{key} change must not verify: {outcome:?}"
        );
    }
}

#[test]
fn verified_true_with_non_200_status_is_not_verified() {
    let fx = fixture();
    let event = proof(&fx);
    let outcome =
        interpret_registry_response(201, &verified_body(&fx, &event), &fx.request, &event, NOW);
    assert!(!matches!(outcome, VerifyOutcome::Verified { .. }));
}

#[test]
fn registry_refusals_keep_their_codes() {
    let fx = fixture();
    let event = proof(&fx);
    for (status, code) in [
        (404, "E_NOSTR_LINK_NOT_FOUND"),
        (403, "E_NOSTR_DOMAIN_MISMATCH"),
        (409, "E_IDENTITY_CONFLICT"),
        (400, "E_STALE"),
    ] {
        let body = format!(r#"{{"verified":false,"error":"x","code":"{code}"}}"#);
        assert_eq!(
            interpret_registry_response(status, body.as_bytes(), &fx.request, &event, NOW),
            VerifyOutcome::Rejected { code: code.into() }
        );
    }
}

#[test]
fn registry_unavailable_is_not_a_rejection_or_verification() {
    let fx = fixture();
    let event = proof(&fx);
    let body = br#"{"verified":false,"error":"x","code":"E_NOSTR_POLICY_UNAVAILABLE"}"#;
    assert_eq!(
        interpret_registry_response(503, body, &fx.request, &event, NOW),
        VerifyOutcome::Unavailable {
            code: "E_NOSTR_POLICY_UNAVAILABLE".into()
        }
    );
    assert_eq!(
        interpret_registry_response(502, b"<html>bad gateway</html>", &fx.request, &event, NOW),
        VerifyOutcome::Unavailable {
            code: "E_REGISTRY_UNAVAILABLE".into()
        }
    );
}

#[test]
fn registry_free_text_codes_are_not_passed_through() {
    let fx = fixture();
    let event = proof(&fx);
    let body = br#"{"verified":false,"code":"<b>click here</b>"}"#;
    assert_eq!(
        interpret_registry_response(400, body, &fx.request, &event, NOW),
        VerifyOutcome::Rejected {
            code: "E_REGISTRY_REJECTED".into()
        }
    );
}

#[test]
fn reply_parent_prefers_reply_marker() {
    let keys = Keys::generate();
    let root = "aa".repeat(32);
    let reply = "bb".repeat(32);
    let event = EventBuilder::new(Kind::Custom(9), "x")
        .tags([
            Tag::parse(["e", root.as_str(), "", "root"]).unwrap(),
            Tag::parse(["e", reply.as_str(), "", "reply"]).unwrap(),
        ])
        .sign_with_keys(&keys)
        .unwrap();
    assert_eq!(parent_event_id(&event), Some(reply));

    let only_root = EventBuilder::new(Kind::Custom(9), "x")
        .tags([Tag::parse(["e", root.as_str(), "", "root"]).unwrap()])
        .sign_with_keys(&keys)
        .unwrap();
    assert_eq!(parent_event_id(&only_root), Some(root));
}
