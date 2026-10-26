import type { SendChannelMessageResult } from "@/shared/api/types";
import { invokeTauri } from "@/shared/api/tauri";

type RawSendChannelMessageResult = {
  event_id: string;
  parent_event_id: string | null;
  root_event_id: string | null;
  depth: number;
  created_at: number;
};

/** Behavior reading exactly as the registry reports it. */
export type AgentVerifyReputation = {
  entropy_score: number | null;
  drift_detected: boolean | null;
  z_score: number | null;
  calibration_stage: string | null;
};

/** Result of checking an agent verification proof. */
export type AgentVerifyOutcome =
  | {
      status: "verified";
      identity: string;
      verifier: string;
      nostr_pubkey: string;
      event_id: string;
      proof_id: string | null;
      /** Current registry link incarnation, when reported. */
      incarnation: string | null;
      checked_at: number;
      /** `null` when the registry reported no behavior reading. */
      reputation: AgentVerifyReputation | null;
      /** Registry trust status; `null` when not reported. */
      blue_tick: boolean | null;
    }
  | { status: "rejected"; code: string }
  | { status: "unavailable"; code: string };

function toSendResult(
  response: RawSendChannelMessageResult,
): SendChannelMessageResult {
  return {
    eventId: response.event_id,
    parentEventId: response.parent_event_id,
    rootEventId: response.root_event_id,
    depth: response.depth,
    createdAt: response.created_at,
  };
}

/** Post a verification request from a managed verifier agent. */
export async function sendAgentVerifyRequest(input: {
  verifierAgentPubkey: string;
  verifierDomain: string;
  proverPubkey: string;
  proverDomain: string;
  channelId: string;
}): Promise<SendChannelMessageResult> {
  return toSendResult(
    await invokeTauri<RawSendChannelMessageResult>(
      "agent_verify_send_request",
      input,
    ),
  );
}

/** Answer a verification request as the managed prover agent it names. */
export async function sendAgentVerifyProof(
  requestEventId: string,
): Promise<SendChannelMessageResult> {
  return toSendResult(
    await invokeTauri<RawSendChannelMessageResult>("agent_verify_send_proof", {
      requestEventId,
    }),
  );
}
