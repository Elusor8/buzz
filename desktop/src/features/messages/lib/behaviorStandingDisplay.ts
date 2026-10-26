// Display wording for the owner's behavior records. Pure functions only: the
// native side has already validated everything, and nothing here changes a
// verdict. Rules carried from the contract:
// - identity and behavior standing are shown separately;
// - calibrating and unknown are never shown as bad;
// - anything not verified and current means nothing can run, whatever the
//   last-known standing was;
// - a queued or retrying notification is never shown as delivered.

import type { AgentVerifyOutcome } from "@/shared/api/tauriAgentVerify";
import type {
  BehaviorListPage,
  BehaviorPagePosition,
  BehaviorStanding,
  BehaviorStandingView,
  BehaviorSubjectMatch,
  OwnerNotificationRecord,
} from "@/shared/api/tauriBehaviorReads";

export type Tone = "ok" | "caution" | "warning" | "danger" | "neutral";

const STANDING_LABELS: Record<BehaviorStanding, string> = {
  normal: "Normal",
  notify: "Shifted",
  reduced: "Reduced",
  denied: "Denied",
  calibrating: "Calibrating",
  unknown: "Not known",
};

const STANDING_TONES: Record<BehaviorStanding, Tone> = {
  normal: "ok",
  notify: "caution",
  reduced: "warning",
  denied: "danger",
  calibrating: "neutral",
  unknown: "neutral",
};

export function standingLabel(standing: BehaviorStanding): string {
  return STANDING_LABELS[standing];
}

export function standingTone(standing: BehaviorStanding): Tone {
  return STANDING_TONES[standing];
}

const UNKNOWN_REASONS: Record<string, string> = {
  not_measured: "No measurements yet.",
  stale: "The latest measurement is out of date.",
  unavailable: "Measurements are unavailable right now.",
  unverifiable: "The measurement could not be verified.",
};

const VERIFICATION_LABELS: Record<
  BehaviorStandingView["verification_status"],
  string
> = {
  verified: "Verified",
  not_measured: "Not measured",
  stale: "Out of date",
  unavailable: "Unavailable",
  unverifiable: "Could not be verified",
};

export function verificationLabel(
  status: BehaviorStandingView["verification_status"],
): string {
  return VERIFICATION_LABELS[status];
}

export type StandingPresentation = {
  /** The standing shown in the badge. */
  label: string;
  tone: Tone;
  /** One sentence on what this means for the peer right now. */
  headline: string;
  /** Extra context, or null. */
  detail: string | null;
  /** Whether the badge shows a last-known (not current) standing. */
  lastKnown: boolean;
  /** Whether anything the peer asks can run, per this snapshot. */
  canTrigger: boolean;
};

function liveHeadline(standing: BehaviorStanding): string {
  switch (standing) {
    case "normal":
      return "Behavior is within its usual pattern.";
    case "notify":
      return "Behavior has shifted. This calls for an owner notification.";
    case "reduced":
      return "Behavior has shifted a lot. It may trigger less than before.";
    case "denied":
      return "It may not trigger anything for you.";
    case "calibrating":
      return "Still gathering measurements. This is not a bad sign.";
    case "unknown":
      return "Behavior is not known yet. This is not a bad sign.";
  }
}

export function presentStanding(
  view: BehaviorStandingView,
  nowMs: number,
): StandingPresentation {
  const current =
    view.current && view.fresh_until_ms !== null && nowMs < view.fresh_until_ms;

  if (!current) {
    const lastKnown = view.decision_ref?.basis === "last_known";
    return {
      label: lastKnown
        ? `Last known: ${standingLabel(view.standing)}`
        : "Not confirmed",
      tone: "neutral",
      headline:
        "Nothing it asks can run right now, because its current standing could not be confirmed.",
      detail:
        view.verification_status === "verified"
          ? "This reading has expired. Check again for a current one."
          : (UNKNOWN_REASONS[view.verification_status] ?? null),
      lastKnown,
      canTrigger: false,
    };
  }

  return {
    label: standingLabel(view.standing),
    tone: standingTone(view.standing),
    headline: liveHeadline(view.standing),
    detail: null,
    lastKnown: false,
    canTrigger: view.executable,
  };
}

export type AllowanceRow = { label: string; value: string };

const ACTION_CLASS_LABELS: Record<string, string> = {
  "conversation.open": "Start a conversation",
  "conversation.turn": "Reply in a conversation",
};

export function actionClassLabel(actionClass: string): string {
  return (
    ACTION_CLASS_LABELS[actionClass] ?? `Unregistered action (${actionClass})`
  );
}

export function allowanceRows(view: BehaviorStandingView): AllowanceRow[] {
  const allowance = view.effective_allowance;
  const classes = allowance.permitted_action_classes;
  return [
    {
      label: "May do",
      value: classes.length
        ? classes.map(actionClassLabel).join(", ")
        : "Nothing",
    },
    {
      label: "Turns per conversation",
      value: String(allowance.max_turns_per_conversation),
    },
    {
      label: "New conversations per hour",
      value: String(allowance.max_new_conversations_per_hour),
    },
    {
      label: "Actions per hour",
      value: String(allowance.max_actions_per_hour),
    },
    {
      label: "Requests per hour",
      value: String(allowance.rate_limit_per_hour),
    },
  ];
}

// ── Identity ────────────────────────────────────────────────────────────────

export type IdentityPresentation = {
  label: string;
  tone: Tone;
  detail: string | null;
};

export function presentIdentity(
  identity: AgentVerifyOutcome,
  subject: BehaviorSubjectMatch,
): IdentityPresentation {
  if (identity.status === "unavailable") {
    return {
      label: "Identity not checked",
      tone: "neutral",
      detail: `The registry could not answer (${identity.code}).`,
    };
  }
  if (identity.status === "rejected") {
    return {
      label: "Identity not verified",
      tone: "warning",
      detail: `The proof did not pass (${identity.code}). No behavior records were read.`,
    };
  }
  const label = `Identity verified as ${identity.identity}`;
  switch (subject.status) {
    case "matched":
      return { label, tone: "ok", detail: null };
    case "not_provisioned":
      return {
        label,
        tone: "ok",
        detail:
          "Your owner service does not track this agent yet, so no behavior records were read.",
      };
    case "no_incarnation":
    case "mismatch":
      return {
        label,
        tone: "ok",
        detail:
          "This agent's registry record does not match your owner service's record, so no behavior records were read.",
      };
    case "identity_not_verified":
      return { label, tone: "ok", detail: null };
  }
}

// ── Notifications ───────────────────────────────────────────────────────────

export function deliveryLabel(record: OwnerNotificationRecord): {
  label: string;
  tone: Tone;
} {
  switch (record.delivery_state) {
    case "queued":
      return { label: "Queued, not delivered yet", tone: "neutral" };
    case "retrying":
      return {
        label: `Retrying, not delivered yet (${record.attempt_count} ${
          record.attempt_count === 1 ? "attempt" : "attempts"
        })`,
        tone: "caution",
      };
    case "delivered":
      return { label: "Accepted by your notification endpoint", tone: "ok" };
    case "failed":
      return {
        label: `Delivery failed${record.failure_code ? ` (${record.failure_code})` : ""}`,
        tone: "danger",
      };
  }
}

export function isFailClosedNotice(record: OwnerNotificationRecord): boolean {
  return (
    record.standing === "unknown" &&
    record.reason_codes.length === 2 &&
    record.reason_codes[0] === "state_unverifiable" &&
    record.reason_codes[1] === "fail_closed"
  );
}

// ── Reason codes ────────────────────────────────────────────────────────────

const REASON_LABELS: Record<string, string> = {
  behavior_shift: "Behavior shifted",
  owner_revoked: "Owner revoked access",
  calibration_incomplete: "Still calibrating",
  not_measured: "Not measured",
  stale: "Measurement out of date",
  unavailable: "Measurement unavailable",
  unverifiable: "Could not be verified",
  recovery_authorized: "Recovery authorized",
  state_unverifiable: "Standing could not be confirmed",
  fail_closed: "Blocked until confirmed",
  standing_denied: "Standing is denied",
  action_class_not_permitted: "Action not permitted",
  turn_allowance_exhausted: "Turn limit reached",
  new_conversation_allowance_exhausted: "New conversation limit reached",
  action_allowance_exhausted: "Action limit reached",
  rate_limit_exhausted: "Rate limit reached",
  baseline_guard: "Blocked by a standing guard",
  restored: "Restored",
  expired: "Authorization expired",
  replayed: "Authorization already used",
  scope_mismatch: "Authorization did not match",
  recovery_refused: "Recovery refused",
};

export function reasonLabel(code: string): string {
  return REASON_LABELS[code] ?? code;
}

// ── Errors ──────────────────────────────────────────────────────────────────

const READ_ERRORS: Record<string, string> = {
  no_binding: "Owner read access is not set up. Add it in Settings, Agents.",
  binding_expired:
    "Owner read access has expired. Ask the owner to reissue it.",
  no_credential: "The read token is missing. Set up owner read access again.",
  secure_storage_unavailable:
    "Secure storage is unavailable, so owner records cannot be read.",
  identity_unattributed: "Not read, because the identity was not attributed.",
  unauthenticated: "Access was refused. The token may be expired or revoked.",
  forbidden: "This read is not allowed for your access.",
  not_found: "Not found for your owner service.",
  decision_fork:
    "Your owner service has conflicting decisions and cannot answer.",
  unavailable: "Your owner service is unavailable right now.",
  invalid_cursor: "The list changed. Reload it from the start.",
  invalid_query: "The request was not accepted.",
  unreachable: "Your owner service could not be reached.",
  tls_config: "The owner service's TLS settings are not usable.",
  invalid_response: "Your owner service sent a response Buzz could not accept.",
  unexpected_response:
    "Your owner service sent a response Buzz could not accept.",
};

export function readErrorLabel(code: string): string {
  return READ_ERRORS[code] ?? "The read did not succeed.";
}

// ── Paging ──────────────────────────────────────────────────────────────────

/** The position to fetch the next page after `page`, or null at the end. */
export function nextPosition<T>(
  page: BehaviorListPage<T>,
  sortKey: (item: T) => [number, string],
): BehaviorPagePosition | null {
  const last = page.items[page.items.length - 1];
  if (!page.next_cursor || last === undefined) {
    return null;
  }
  const [lastTime, lastId] = sortKey(last);
  return {
    cursor: page.next_cursor,
    as_of_ms: page.as_of_ms,
    last_time_ms: lastTime,
    last_id: lastId,
  };
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleString();
}
