// LOCAL ONLY: synthetic fixtures.
import assert from "node:assert/strict";
import test from "node:test";

import {
  deliveryLabel,
  isFailClosedNotice,
  nextPosition,
  presentIdentity,
  presentStanding,
  standingTone,
} from "./behaviorStandingDisplay.ts";

const zero = {
  max_turns_per_conversation: 0,
  max_new_conversations_per_hour: 0,
  max_actions_per_hour: 0,
  permitted_action_classes: [],
  rate_limit_per_hour: 0,
};

function view(overrides = {}) {
  return {
    schema_version: "1.0",
    as_of_ms: 10_000,
    owner_id: "fixture-owner",
    mailbox_id: "00000000-0000-4000-8000-000000000001",
    subject_agent_id: "sub1_x",
    identity_validity: "valid",
    standing: "normal",
    decision_ref: { id: "d", basis: "current", digest_sha256: "b".repeat(64) },
    evidence_version: 3,
    window: { start_ms: 1, end_ms: 2 },
    policy_version: 2,
    effective_allowance: { ...zero, max_turns_per_conversation: 4 },
    executable: true,
    checked_at_ms: 9_000,
    fresh_until_ms: 70_000,
    verification_status: "verified",
    reason_code: null,
    current: true,
    ...overrides,
  };
}

test("calibrating and unknown are never shown as bad", () => {
  assert.equal(standingTone("calibrating"), "neutral");
  assert.equal(standingTone("unknown"), "neutral");
  for (const standing of ["calibrating", "unknown"]) {
    const shown = presentStanding(view({ standing }), 10_000);
    assert.equal(shown.tone, "neutral");
    assert.match(shown.headline, /not a bad sign/);
  }
});

test("a last-known normal standing never lets anything run", () => {
  const shown = presentStanding(
    view({
      current: false,
      verification_status: "stale",
      decision_ref: {
        id: "d",
        basis: "last_known",
        digest_sha256: "b".repeat(64),
      },
      executable: false,
      effective_allowance: zero,
      fresh_until_ms: null,
      reason_code: "fail_closed",
    }),
    10_000,
  );
  assert.equal(shown.canTrigger, false);
  assert.equal(shown.lastKnown, true);
  assert.equal(shown.label, "Last known: Normal");
  assert.equal(shown.tone, "neutral");
});

test("an expired verified reading is not current", () => {
  const shown = presentStanding(view(), 70_000);
  assert.equal(shown.canTrigger, false);
  assert.equal(shown.label, "Not confirmed");
});

test("a current reduced standing is shown with its tone", () => {
  const shown = presentStanding(view({ standing: "reduced" }), 10_000);
  assert.equal(shown.label, "Reduced");
  assert.equal(shown.tone, "warning");
  assert.equal(shown.canTrigger, true);
});

test("queued and retrying are never shown as delivered", () => {
  const base = { reason_codes: [], standing: "notify", attempt_count: 1 };
  assert.match(
    deliveryLabel({ ...base, delivery_state: "queued" }).label,
    /not delivered/,
  );
  assert.match(
    deliveryLabel({ ...base, delivery_state: "retrying" }).label,
    /not delivered/,
  );
  assert.doesNotMatch(
    deliveryLabel({ ...base, delivery_state: "delivered", delivered_at_ms: 1 })
      .label,
    /read/i,
  );
  assert.match(
    deliveryLabel({
      ...base,
      delivery_state: "failed",
      failure_code: "timeout",
    }).label,
    /failed \(timeout\)/,
  );
});

test("fail-closed notices are recognized exactly", () => {
  assert.equal(
    isFailClosedNotice({
      standing: "unknown",
      reason_codes: ["state_unverifiable", "fail_closed"],
    }),
    true,
  );
  assert.equal(
    isFailClosedNotice({
      standing: "unknown",
      reason_codes: ["fail_closed", "state_unverifiable"],
    }),
    false,
  );
});

test("identity is reported separately from standing", () => {
  const verified = {
    status: "verified",
    identity: "example.viz",
    verifier: "v.viz",
    nostr_pubkey: "a".repeat(64),
    event_id: "e".repeat(64),
    proof_id: null,
    incarnation: "0".repeat(32),
    checked_at: 0,
    reputation: null,
    blue_tick: null,
  };
  const matched = presentIdentity(verified, {
    status: "matched",
    domain: "example.viz",
    subject_agent_id: "sub1_x",
  });
  assert.equal(matched.label, "Identity verified as example.viz");
  const unprovisioned = presentIdentity(verified, {
    status: "not_provisioned",
  });
  assert.equal(unprovisioned.tone, "ok");
  assert.match(unprovisioned.detail, /no behavior records were read/);
  const rejected = presentIdentity(
    { status: "rejected", code: "E_PROOF_EXPIRED" },
    { status: "identity_not_verified" },
  );
  assert.equal(rejected.label, "Identity not verified");
});

test("paging continues only with a cursor and items", () => {
  const key = (item) => [item.t, item.id];
  assert.equal(
    nextPosition(
      { as_of_ms: 5, items: [{ t: 1, id: "a" }], next_cursor: null },
      key,
    ),
    null,
  );
  assert.deepEqual(
    nextPosition(
      {
        as_of_ms: 5,
        items: [
          { t: 1, id: "a" },
          { t: 2, id: "b" },
        ],
        next_cursor: "c",
      },
      key,
    ),
    { cursor: "c", as_of_ms: 5, last_time_ms: 2, last_id: "b" },
  );
});
