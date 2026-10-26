// Display-only parsing of agent verification messages. Every security
// decision (signing, binding, registry check) happens natively from relay
// copies of these events; nothing here is trusted.

export const AGENT_VERIFY_REQUEST_MARKER =
  "<!-- zipviz:agent-verify-request:v1 -->";
export const AGENT_VERIFY_PROOF_MARKER =
  "<!-- zipviz:agent-verify-proof:v1 -->";

/** How long a proof stays checkable, matching the registry window. */
export const AGENT_VERIFY_FRESHNESS_SECONDS = 300;

const VIZ_DOMAIN =
  /^[a-z0-9][a-z0-9-]{0,19}\.(?:[a-z0-9][a-z0-9-]{0,19}\.)?viz$/;
const HEX64 = /^[0-9a-f]{64}$/;

export type AgentVerifyRequestContent = {
  verifier: string;
  verifierPubkey: string;
  prover: string;
  proverPubkey: string;
};

export type AgentVerifyProofContent = {
  signerPubkey: string | null;
  createdAt: number | null;
};

function markedPayload(content: string, marker: string): string | null {
  const trimmed = content.trimStart();
  if (!trimmed.startsWith(marker)) {
    return null;
  }
  return (
    trimmed
      .slice(marker.length)
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? null
  );
}

function parseJsonObject(text: string | null): Record<string, unknown> | null {
  if (!text) {
    return null;
  }
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function isAgentVerifyDomain(value: string): boolean {
  return VIZ_DOMAIN.test(value);
}

export function parseAgentVerifyRequestContent(
  content: string,
): AgentVerifyRequestContent | null {
  const json = parseJsonObject(
    markedPayload(content, AGENT_VERIFY_REQUEST_MARKER),
  );
  if (!json) {
    return null;
  }
  const { verifier, verifier_pubkey, prover, prover_pubkey } = json;
  if (
    typeof verifier !== "string" ||
    typeof prover !== "string" ||
    typeof verifier_pubkey !== "string" ||
    typeof prover_pubkey !== "string" ||
    !VIZ_DOMAIN.test(verifier) ||
    !VIZ_DOMAIN.test(prover) ||
    !HEX64.test(verifier_pubkey) ||
    !HEX64.test(prover_pubkey)
  ) {
    return null;
  }
  return {
    verifier,
    verifierPubkey: verifier_pubkey,
    prover,
    proverPubkey: prover_pubkey,
  };
}

/**
 * Recognize a proof message. Malformed proofs still count as proofs so the
 * app shows them as rejected rather than as plain text.
 */
export function parseAgentVerifyProofContent(
  content: string,
): AgentVerifyProofContent | null {
  if (!content.trimStart().startsWith(AGENT_VERIFY_PROOF_MARKER)) {
    return null;
  }
  const json = parseJsonObject(
    markedPayload(content, AGENT_VERIFY_PROOF_MARKER),
  );
  const pubkey = json?.pubkey;
  const createdAt = json?.created_at;
  return {
    signerPubkey:
      typeof pubkey === "string" && HEX64.test(pubkey) ? pubkey : null,
    createdAt:
      typeof createdAt === "number" && Number.isSafeInteger(createdAt)
        ? createdAt
        : null,
  };
}
