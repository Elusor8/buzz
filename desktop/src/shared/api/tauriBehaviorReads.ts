import type { AgentVerifyOutcome } from "@/shared/api/tauriAgentVerify";
import { invokeTauri } from "@/shared/api/tauri";

// Read-only views of the receiving owner's behavior records. All decoding and
// validation happens natively; these types mirror what the native side
// returns after it has accepted a response.

export type BehaviorStanding =
  | "normal"
  | "notify"
  | "reduced"
  | "denied"
  | "calibrating"
  | "unknown";

export type BehaviorWindow = { start_ms: number; end_ms: number };

export type BehaviorAllowance = {
  max_turns_per_conversation: number;
  max_new_conversations_per_hour: number;
  max_actions_per_hour: number;
  permitted_action_classes: string[];
  rate_limit_per_hour: number;
};

export type BehaviorStandingView = {
  schema_version: "1.0";
  as_of_ms: number;
  owner_id: string;
  mailbox_id: string;
  subject_agent_id: string;
  identity_validity: "valid" | "invalid" | "unverified";
  standing: BehaviorStanding;
  decision_ref: {
    id: string;
    basis: "current" | "last_known";
    digest_sha256: string;
  } | null;
  evidence_version: number | null;
  window: BehaviorWindow | null;
  policy_version: number | null;
  effective_allowance: BehaviorAllowance;
  executable: boolean;
  checked_at_ms: number;
  fresh_until_ms: number | null;
  verification_status:
    | "verified"
    | "not_measured"
    | "stale"
    | "unavailable"
    | "unverifiable";
  reason_code: string | null;
  /** Verified and still inside its freshness window when read. */
  current: boolean;
};

export type BehaviorSignature = {
  alg: string;
  key_id: string;
  value_base64url: string;
};

export type DeniedAttemptRecord = {
  id: string;
  attempt_id: string;
  subject_agent_id: string;
  decision_id: string;
  policy_version: number;
  attempted_action_class: string;
  conversation_id?: string;
  timestamp_ms: number;
  reason_code: string;
  outcome: "denied" | "non_executable";
  receipt_id: string;
  signature: BehaviorSignature;
};

export type OwnerNotificationRecord = {
  notification_id: string;
  episode_id: string;
  subject_agent_id: string;
  decision_id: string | null;
  standing: BehaviorStanding;
  reason_codes: string[];
  evidence_version: number | null;
  window: BehaviorWindow | null;
  policy_version: number | null;
  created_at_ms: number;
  delivery_state: "queued" | "retrying" | "delivered" | "failed";
  attempt_count: number;
  last_attempt_at_ms?: number;
  delivered_at_ms?: number;
  failure_code?: string;
};

export type RestorationReceiptRecord = {
  id: string;
  recovery_authorization_id: string;
  previous_decision_id: string;
  new_decision_id: string;
  subject_agent_id: string;
  policy_version: number;
  evidence_version: number;
  window: BehaviorWindow;
  effective_at_ms: number;
  result: "restored" | "refused";
  reason_code: string;
  issued_at_ms: number;
  signature: BehaviorSignature;
};

export type BehaviorListPage<T> = {
  schema_version: "1.0";
  as_of_ms: number;
  subject_agent_id: string | null;
  items: T[];
  next_cursor: string | null;
};

export type BehaviorReadResult<T> =
  | { status: "ok"; data: T }
  | { status: "not_granted" }
  | { status: "error"; code: string };

export type BehaviorSubjectMatch =
  | { status: "identity_not_verified" }
  | { status: "no_incarnation" }
  | { status: "not_provisioned" }
  | { status: "mismatch" }
  | { status: "matched"; domain: string; subject_agent_id: string };

export type PeerBehavior = {
  identity: AgentVerifyOutcome;
  subject: BehaviorSubjectMatch;
  standing: BehaviorReadResult<BehaviorStandingView>;
  denied_attempts: BehaviorReadResult<BehaviorListPage<DeniedAttemptRecord>>;
  recovery_receipts: BehaviorReadResult<
    BehaviorListPage<RestorationReceiptRecord>
  >;
};

export type BehaviorBindingStatus =
  | { state: "none" }
  | { state: "invalid" }
  | { state: "expired"; expires_at_ms: number }
  | { state: "no_credential" }
  | { state: "secure_storage_unavailable" }
  | {
      state: "active";
      owner_id: string;
      mailbox_id: string;
      base_url: string;
      scopes: string[];
      expires_at_ms: number;
      subjects: { domain: string; subject_agent_id: string }[];
    };

/** Where the previous page of a list ended. */
export type BehaviorPagePosition = {
  cursor: string;
  as_of_ms: number;
  last_time_ms: number;
  last_id: string;
};

export function getBehaviorBindingStatus(): Promise<BehaviorBindingStatus> {
  return invokeTauri<BehaviorBindingStatus>("behavior_binding_status");
}

/** Opens native file pickers for the binding and token files. */
export function importBehaviorBinding(): Promise<BehaviorBindingStatus> {
  return invokeTauri<BehaviorBindingStatus>("behavior_import_binding");
}

export function removeBehaviorBinding(): Promise<BehaviorBindingStatus> {
  return invokeTauri<BehaviorBindingStatus>("behavior_remove_binding");
}

/** Check a proof's identity, then read that peer's behavior records. */
export function readPeerBehavior(proofEventId: string): Promise<PeerBehavior> {
  return invokeTauri<PeerBehavior>("behavior_read_peer", { proofEventId });
}

export function readPeerBehaviorPage<T>(
  list: "denied_attempts" | "recovery_receipts",
  subjectAgentId: string,
  position: BehaviorPagePosition,
): Promise<BehaviorReadResult<BehaviorListPage<T>>> {
  return invokeTauri<BehaviorReadResult<BehaviorListPage<T>>>(
    "behavior_read_list",
    { list, subjectAgentId, position },
  );
}

export function readOwnerNotifications(
  position: BehaviorPagePosition | null,
): Promise<BehaviorReadResult<BehaviorListPage<OwnerNotificationRecord>>> {
  return invokeTauri<
    BehaviorReadResult<BehaviorListPage<OwnerNotificationRecord>>
  >("behavior_read_list", {
    list: "notifications",
    subjectAgentId: null,
    position,
  });
}
