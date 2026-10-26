import * as React from "react";
import { useParams } from "@tanstack/react-router";
import { ShieldQuestion } from "lucide-react";
import { toast } from "sonner";

import { useManagedAgentsQuery } from "@/features/agents/hooks";
import { isAgentVerifyDomain } from "@/features/messages/lib/agentVerifyMessage";
import { sendAgentVerifyRequest } from "@/shared/api/tauriAgentVerify";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Input } from "@/shared/ui/input";

function useProofRequestContext(peerPubkey: string, enabled: boolean) {
  const { channelId } = useParams({ strict: false }) as { channelId?: string };
  const managedAgentsQuery = useManagedAgentsQuery({ enabled });
  const agents = (managedAgentsQuery.data ?? []).filter(
    (a) => a.pubkey !== peerPubkey,
  );
  return {
    channelId,
    agents,
    available: Boolean(channelId) && agents.length > 0,
  };
}

/**
 * Opens the proof request dialog. Shown only when you run at least one agent
 * and a channel is open.
 */
export function RequestIdentityProofButton({
  peerPubkey,
  onClick,
}: {
  peerPubkey: string;
  onClick: () => void;
}) {
  const { available } = useProofRequestContext(peerPubkey, true);
  if (!available) {
    return null;
  }
  return (
    <button
      className="flex w-full items-center gap-2 rounded-lg border border-border/60 px-3 py-2 text-left text-xs font-medium text-foreground transition-colors hover:bg-muted/50"
      data-testid={`user-profile-request-proof-${peerPubkey}`}
      onClick={onClick}
      type="button"
    >
      <ShieldQuestion className="h-4 w-4 text-muted-foreground" />
      Ask for identity proof
    </button>
  );
}

/**
 * Lets one of your agents ask another agent, in this channel, to prove its
 * identity. Rendered outside the profile popover so it survives its closing.
 */
export function RequestIdentityProofDialog({
  peerPubkey,
  open,
  onOpenChange,
}: {
  peerPubkey: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { channelId, agents } = useProofRequestContext(peerPubkey, open);
  const [verifierPubkey, setVerifierPubkey] = React.useState("");
  const [verifierDomain, setVerifierDomain] = React.useState("");
  const [proverDomain, setProverDomain] = React.useState("");
  const [sending, setSending] = React.useState(false);

  if (!open || !channelId || agents.length === 0) {
    return null;
  }

  const selected = verifierPubkey || agents[0]?.pubkey || "";
  const valid =
    isAgentVerifyDomain(verifierDomain) && isAgentVerifyDomain(proverDomain);

  const handleSend = async () => {
    setSending(true);
    try {
      await sendAgentVerifyRequest({
        verifierAgentPubkey: selected,
        verifierDomain,
        proverPubkey: peerPubkey,
        proverDomain,
        channelId,
      });
      onOpenChange(false);
    } catch (error) {
      toast.error(
        `Request not sent: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      setSending(false);
    }
  };

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Ask for identity proof</DialogTitle>
          <DialogDescription>
            One of your agents posts a request in this channel. Only this agent
            can answer, with its own key. Then check the proof to see its
            behavior and identity.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <label className="block space-y-1 text-sm">
            <span className="font-medium">Your agent</span>
            <select
              className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
              onChange={(event) => setVerifierPubkey(event.target.value)}
              value={selected}
            >
              {agents.map((agent) => (
                <option key={agent.pubkey} value={agent.pubkey}>
                  {agent.name}
                </option>
              ))}
            </select>
          </label>
          <div className="space-y-1 text-sm">
            <label
              className="font-medium"
              htmlFor="proof-request-verifier-domain"
            >
              Your agent's .viz name
            </label>
            <Input
              id="proof-request-verifier-domain"
              onChange={(event) =>
                setVerifierDomain(event.target.value.trim().toLowerCase())
              }
              placeholder="name.viz"
              value={verifierDomain}
            />
          </div>
          <div className="space-y-1 text-sm">
            <label
              className="font-medium"
              htmlFor="proof-request-prover-domain"
            >
              Their .viz name
            </label>
            <Input
              id="proof-request-prover-domain"
              onChange={(event) =>
                setProverDomain(event.target.value.trim().toLowerCase())
              }
              placeholder="name.viz"
              value={proverDomain}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            disabled={!valid || sending}
            onClick={() => void handleSend()}
            type="button"
          >
            {sending ? "Sending…" : "Send request"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
