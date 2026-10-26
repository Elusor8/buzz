import * as React from "react";
import { BadgeCheck, ShieldQuestion } from "lucide-react";
import { toast } from "sonner";

import type {
  AgentVerifyProofContent,
  AgentVerifyRequestContent,
} from "@/features/messages/lib/agentVerifyMessage";
import { sendAgentVerifyProof } from "@/shared/api/tauriAgentVerify";
import {
  readPeerBehavior,
  type PeerBehavior,
} from "@/shared/api/tauriBehaviorReads";
import {
  Attachment,
  AttachmentAction,
  AttachmentActions,
  AttachmentContent,
  AttachmentDescription,
  AttachmentMedia,
  AttachmentTitle,
} from "@/shared/ui/attachment";

import { PeerBehaviorDialog } from "./PeerBehaviorDialog";

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A request asking an agent to prove its identity. */
export function AgentVerifyRequestAttachment({
  eventId,
  request,
}: {
  eventId: string;
  request: AgentVerifyRequestContent;
}) {
  const [sending, setSending] = React.useState(false);

  const handleSend = React.useCallback(
    async (event: React.MouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      event.stopPropagation();
      setSending(true);
      try {
        await sendAgentVerifyProof(eventId);
      } catch (error) {
        toast.error(`Proof not sent: ${errorText(error)}`);
      } finally {
        setSending(false);
      }
    },
    [eventId],
  );

  return (
    <Attachment
      className="mt-1 max-w-md"
      data-testid="agent-verify-request"
      size="default"
    >
      <AttachmentMedia aria-hidden="true">
        <ShieldQuestion className="h-4 w-4" />
      </AttachmentMedia>
      <AttachmentContent>
        <AttachmentTitle>
          {request.verifier} asked {request.prover} to prove its identity
        </AttachmentTitle>
        <AttachmentDescription>
          Only the agent named here can answer, with its own key.
        </AttachmentDescription>
      </AttachmentContent>
      <AttachmentActions>
        <AttachmentAction
          disabled={sending}
          onClick={handleSend}
          size="xs"
          type="button"
        >
          {sending ? "Sending…" : "Send proof"}
        </AttachmentAction>
      </AttachmentActions>
    </Attachment>
  );
}

/** An agent's identity proof; checking it also reads the owner's records. */
export function AgentVerifyProofAttachment({
  eventId,
}: {
  eventId: string;
  proof: AgentVerifyProofContent;
}) {
  const [checking, setChecking] = React.useState(false);
  const [behavior, setBehavior] = React.useState<PeerBehavior | null>(null);

  const handleCheck = React.useCallback(
    async (event: React.MouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      event.stopPropagation();
      setChecking(true);
      try {
        setBehavior(await readPeerBehavior(eventId));
      } catch (error) {
        toast.error(`Check did not run: ${errorText(error)}`);
      } finally {
        setChecking(false);
      }
    },
    [eventId],
  );

  return (
    <>
      <Attachment
        className="mt-1 max-w-md"
        data-testid="agent-verify-proof"
        size="default"
      >
        <AttachmentMedia aria-hidden="true">
          <BadgeCheck className="h-4 w-4" />
        </AttachmentMedia>
        <AttachmentContent>
          <AttachmentTitle>Identity proof</AttachmentTitle>
          <AttachmentDescription>
            Check it within 5 minutes to see this agent's behavior and identity.
          </AttachmentDescription>
        </AttachmentContent>
        <AttachmentActions>
          <AttachmentAction
            disabled={checking}
            onClick={handleCheck}
            size="xs"
            type="button"
          >
            {checking ? "Checking…" : "Check"}
          </AttachmentAction>
        </AttachmentActions>
      </Attachment>
      {behavior ? (
        <PeerBehaviorDialog
          behavior={behavior}
          onOpenChange={(open) => {
            if (!open) {
              setBehavior(null);
            }
          }}
          open
        />
      ) : null}
    </>
  );
}
