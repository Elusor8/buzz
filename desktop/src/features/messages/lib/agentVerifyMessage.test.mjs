import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_VERIFY_PROOF_MARKER,
  AGENT_VERIFY_REQUEST_MARKER,
  isAgentVerifyDomain,
  parseAgentVerifyProofContent,
  parseAgentVerifyRequestContent,
} from "./agentVerifyMessage.ts";

const A = "a".repeat(64);
const B = "b".repeat(64);

function request(fields) {
  return `${AGENT_VERIFY_REQUEST_MARKER}\n${JSON.stringify(fields)}\nfallback`;
}

test("parses a well-formed request", () => {
  assert.deepEqual(
    parseAgentVerifyRequestContent(
      request({
        verifier: "alpha.viz",
        verifier_pubkey: A,
        prover: "bravo.viz",
        prover_pubkey: B,
        nonce: "0".repeat(32),
      }),
    ),
    {
      verifier: "alpha.viz",
      verifierPubkey: A,
      prover: "bravo.viz",
      proverPubkey: B,
    },
  );
});

test("ignores plain text and malformed requests", () => {
  assert.equal(parseAgentVerifyRequestContent("hello"), null);
  assert.equal(
    parseAgentVerifyRequestContent(`${AGENT_VERIFY_REQUEST_MARKER}\nnot json`),
    null,
  );
  assert.equal(
    parseAgentVerifyRequestContent(
      request({
        verifier: "Alpha.viz",
        verifier_pubkey: A,
        prover: "bravo.viz",
        prover_pubkey: B,
      }),
    ),
    null,
  );
});

test("recognizes proofs, including malformed ones", () => {
  const proof = parseAgentVerifyProofContent(
    `${AGENT_VERIFY_PROOF_MARKER}\n${JSON.stringify({ pubkey: B, created_at: 1800000000 })}`,
  );
  assert.deepEqual(proof, { signerPubkey: B, createdAt: 1800000000 });
  assert.deepEqual(
    parseAgentVerifyProofContent(`${AGENT_VERIFY_PROOF_MARKER}\n{broken`),
    { signerPubkey: null, createdAt: null },
  );
  assert.equal(parseAgentVerifyProofContent("hello"), null);
});

test("domain check matches registry shape", () => {
  assert.equal(isAgentVerifyDomain("relay-bot.demo.viz"), true);
  assert.equal(isAgentVerifyDomain("a.b.c.viz"), false);
  assert.equal(isAgentVerifyDomain("bravo.com"), false);
});
