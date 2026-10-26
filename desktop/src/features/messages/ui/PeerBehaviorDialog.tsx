import * as React from "react";

import {
  allowanceRows,
  formatTime,
  nextPosition,
  presentIdentity,
  presentStanding,
  readErrorLabel,
  reasonLabel,
  actionClassLabel,
  type Tone,
} from "@/features/messages/lib/behaviorStandingDisplay";
import {
  readPeerBehaviorPage,
  type BehaviorListPage,
  type BehaviorReadResult,
  type DeniedAttemptRecord,
  type PeerBehavior,
  type RestorationReceiptRecord,
} from "@/shared/api/tauriBehaviorReads";
import { Badge, type BadgeProps } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";

const TONE_BADGE: Record<Tone, BadgeProps["variant"]> = {
  ok: "success",
  caution: "info",
  warning: "warning",
  danger: "destructive",
  neutral: "secondary",
};

function ToneBadge({
  tone,
  children,
}: {
  tone: Tone;
  children: React.ReactNode;
}) {
  return <Badge variant={TONE_BADGE[tone]}>{children}</Badge>;
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

function StandingSection({ result }: { result: PeerBehavior["standing"] }) {
  if (result.status === "not_granted") {
    return <Muted>Your access does not include behavior standing.</Muted>;
  }
  if (result.status === "error") {
    return (
      <div className="space-y-1">
        <ToneBadge tone="neutral">Not confirmed</ToneBadge>
        <p className="text-sm font-medium">
          Nothing it asks can run until its standing is confirmed.
        </p>
        <Muted>{readErrorLabel(result.code)}</Muted>
      </div>
    );
  }
  const view = result.data;
  const shown = presentStanding(view, Date.now());
  return (
    <div className="space-y-3" data-testid="peer-behavior-standing">
      <div className="space-y-1">
        <ToneBadge tone={shown.tone}>{shown.label}</ToneBadge>
        <p className="text-sm font-medium">{shown.headline}</p>
        {shown.detail ? <Muted>{shown.detail}</Muted> : null}
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Can trigger actions</dt>
        <dd>{shown.canTrigger ? "Yes, within these limits" : "No"}</dd>
        {allowanceRows(view).map((row) => (
          <React.Fragment key={row.label}>
            <dt className="text-muted-foreground">{row.label}</dt>
            <dd>{row.value}</dd>
          </React.Fragment>
        ))}
        <dt className="text-muted-foreground">Checked</dt>
        <dd>{formatTime(view.checked_at_ms)}</dd>
        {view.fresh_until_ms !== null ? (
          <>
            <dt className="text-muted-foreground">Good until</dt>
            <dd>{formatTime(view.fresh_until_ms)}</dd>
          </>
        ) : null}
        {view.decision_ref ? (
          <>
            <dt className="text-muted-foreground">Signed decision</dt>
            <dd className="truncate font-mono text-xs">
              {view.decision_ref.id}
              {view.policy_version !== null
                ? ` · policy v${view.policy_version}`
                : ""}
              {view.evidence_version !== null
                ? ` · evidence v${view.evidence_version}`
                : ""}
            </dd>
          </>
        ) : null}
      </dl>
    </div>
  );
}

type ListState<T> = {
  result: BehaviorReadResult<BehaviorListPage<T>>;
  items: T[];
};

function usePagedList<T>(
  initial: BehaviorReadResult<BehaviorListPage<T>>,
  list: "denied_attempts" | "recovery_receipts",
  subjectAgentId: string | null,
  sortKey: (item: T) => [number, string],
) {
  const [state, setState] = React.useState<ListState<T>>(() => ({
    result: initial,
    items: initial.status === "ok" ? initial.data.items : [],
  }));
  const [loading, setLoading] = React.useState(false);

  const position =
    state.result.status === "ok"
      ? nextPosition(state.result.data, sortKey)
      : null;

  const loadMore = React.useCallback(async () => {
    if (!position || !subjectAgentId) {
      return;
    }
    setLoading(true);
    try {
      const result = await readPeerBehaviorPage<T>(
        list,
        subjectAgentId,
        position,
      );
      setState((previous) => ({
        result,
        // A failed page never keeps a partial traversal around.
        items:
          result.status === "ok"
            ? [...previous.items, ...result.data.items]
            : [],
      }));
    } catch {
      setState({
        result: { status: "error", code: "unexpected_response" },
        items: [],
      });
    } finally {
      setLoading(false);
    }
  }, [list, position, subjectAgentId]);

  return { state, loading, canLoadMore: position !== null, loadMore };
}

function ListBody<T>({
  label,
  state,
  loading,
  canLoadMore,
  loadMore,
  empty,
  render,
  itemKey,
}: {
  label: string;
  state: ListState<T>;
  loading: boolean;
  canLoadMore: boolean;
  loadMore: () => void;
  empty: string;
  render: (item: T) => React.ReactNode;
  itemKey: (item: T) => string;
}) {
  if (state.result.status === "not_granted") {
    return <Muted>Your access does not include {label}.</Muted>;
  }
  if (state.result.status === "error") {
    return <Muted>{readErrorLabel(state.result.code)}</Muted>;
  }
  if (state.items.length === 0) {
    return <Muted>{empty}</Muted>;
  }
  return (
    <div className="space-y-2">
      <ul className="space-y-2">
        {state.items.map((item) => (
          <li
            className="rounded-lg border border-border/60 px-3 py-2 text-sm"
            key={itemKey(item)}
          >
            {render(item)}
          </li>
        ))}
      </ul>
      {canLoadMore ? (
        <Button
          disabled={loading}
          onClick={loadMore}
          size="sm"
          type="button"
          variant="outline"
        >
          {loading ? "Loading…" : "Show more"}
        </Button>
      ) : null}
    </div>
  );
}

function DeniedAttempt({ item }: { item: DeniedAttemptRecord }) {
  return (
    <div className="space-y-0.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">
          {actionClassLabel(item.attempted_action_class)}
        </span>
        <ToneBadge tone="neutral">
          {item.outcome === "denied" ? "Blocked" : "Held, not run"}
        </ToneBadge>
      </div>
      <Muted>
        {reasonLabel(item.reason_code)} · {formatTime(item.timestamp_ms)}
      </Muted>
      <p className="truncate font-mono text-xs text-muted-foreground">
        Signed receipt {item.receipt_id}
      </p>
    </div>
  );
}

function RecoveryReceipt({ item }: { item: RestorationReceiptRecord }) {
  const restored = item.result === "restored";
  return (
    <div className="space-y-0.5">
      <div className="flex flex-wrap items-center gap-2">
        <ToneBadge tone={restored ? "ok" : "neutral"}>
          {restored ? "Restored" : "Refused"}
        </ToneBadge>
        <span>{reasonLabel(item.reason_code)}</span>
      </div>
      <Muted>
        {restored ? "Took effect" : "Decided"}{" "}
        {formatTime(item.effective_at_ms)}
      </Muted>
      <p className="truncate font-mono text-xs text-muted-foreground">
        {item.previous_decision_id} → {item.new_decision_id} · authorization{" "}
        {item.recovery_authorization_id}
      </p>
    </div>
  );
}

export function PeerBehaviorDialog({
  behavior,
  onOpenChange,
  open,
}: {
  behavior: PeerBehavior;
  onOpenChange: (open: boolean) => void;
  open: boolean;
}) {
  const subjectAgentId =
    behavior.subject.status === "matched"
      ? behavior.subject.subject_agent_id
      : null;
  const identity = presentIdentity(behavior.identity, behavior.subject);
  const denied = usePagedList<DeniedAttemptRecord>(
    behavior.denied_attempts,
    "denied_attempts",
    subjectAgentId,
    (item) => [item.timestamp_ms, item.attempt_id],
  );
  const recovery = usePagedList<RestorationReceiptRecord>(
    behavior.recovery_receipts,
    "recovery_receipts",
    subjectAgentId,
    (item) => [item.issued_at_ms, item.id],
  );
  const title =
    behavior.identity.status === "verified"
      ? behavior.identity.identity
      : "Agent";

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            What your owner service reports about this agent. Buzz shows these
            records; your owner service enforces them.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          <Section title="Behavior">
            {subjectAgentId ? (
              <StandingSection result={behavior.standing} />
            ) : (
              <Muted>
                {behavior.standing.status === "error"
                  ? readErrorLabel(behavior.standing.code)
                  : "Not read."}
              </Muted>
            )}
          </Section>

          <Section title="Identity">
            <div className="space-y-1" data-testid="peer-behavior-identity">
              <ToneBadge tone={identity.tone}>{identity.label}</ToneBadge>
              {identity.detail ? <Muted>{identity.detail}</Muted> : null}
            </div>
          </Section>

          {subjectAgentId ? (
            <>
              <Section title="Blocked attempts">
                <ListBody
                  empty="No blocked attempts."
                  itemKey={(item) => item.attempt_id}
                  label="blocked attempts"
                  render={(item) => <DeniedAttempt item={item} />}
                  {...denied}
                />
              </Section>
              <Section title="Recovery">
                <ListBody
                  empty="No recovery receipts."
                  itemKey={(item) => item.id}
                  label="recovery receipts"
                  render={(item) => <RecoveryReceipt item={item} />}
                  {...recovery}
                />
              </Section>
            </>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
