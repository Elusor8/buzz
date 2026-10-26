import * as React from "react";
import { toast } from "sonner";

import {
  deliveryLabel,
  formatTime,
  isFailClosedNotice,
  nextPosition,
  readErrorLabel,
  reasonLabel,
  standingLabel,
  standingTone,
  type Tone,
} from "@/features/messages/lib/behaviorStandingDisplay";
import {
  getBehaviorBindingStatus,
  importBehaviorBinding,
  readOwnerNotifications,
  removeBehaviorBinding,
  type BehaviorBindingStatus,
  type BehaviorListPage,
  type BehaviorReadResult,
  type OwnerNotificationRecord,
} from "@/shared/api/tauriBehaviorReads";
import { Badge, type BadgeProps } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { SettingsOptionGroup, SettingsOptionRow } from "./SettingsOptionGroup";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

const TONE_BADGE: Record<Tone, BadgeProps["variant"]> = {
  ok: "success",
  caution: "info",
  warning: "warning",
  danger: "destructive",
  neutral: "secondary",
};

function statusText(status: BehaviorBindingStatus | null): string {
  switch (status?.state) {
    case undefined:
      return "Checking…";
    case "none":
      return "Not set up. Your owner provides a read binding file and a read token file.";
    case "invalid":
      return "The saved read binding is not valid. Remove it and set it up again.";
    case "expired":
      return `Expired ${formatTime(status.expires_at_ms)}. Ask the owner to reissue access.`;
    case "no_credential":
      return "The read token is missing. Set up access again.";
    case "secure_storage_unavailable":
      return "Secure storage is unavailable, so owner records cannot be read.";
    case "active":
      return `Active until ${formatTime(status.expires_at_ms)}. Tracks ${
        status.subjects.length
      } ${status.subjects.length === 1 ? "agent" : "agents"}.`;
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function Notification({
  item,
  names,
}: {
  item: OwnerNotificationRecord;
  names: Map<string, string>;
}) {
  const delivery = deliveryLabel(item);
  const failClosed = isFailClosedNotice(item);
  return (
    <li className="space-y-1 rounded-lg border border-border/60 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">
          {names.get(item.subject_agent_id) ?? "Agent not in your binding"}
        </span>
        <Badge
          variant={
            TONE_BADGE[failClosed ? "neutral" : standingTone(item.standing)]
          }
        >
          {failClosed
            ? "Blocked until confirmed"
            : standingLabel(item.standing)}
        </Badge>
      </div>
      <p className="text-muted-foreground">
        {item.reason_codes.map(reasonLabel).join(", ") || "No reason given"} ·{" "}
        {formatTime(item.created_at_ms)}
      </p>
      <Badge variant={TONE_BADGE[delivery.tone]}>{delivery.label}</Badge>
    </li>
  );
}

function NotificationsList({ names }: { names: Map<string, string> }) {
  const [result, setResult] = React.useState<BehaviorReadResult<
    BehaviorListPage<OwnerNotificationRecord>
  > | null>(null);
  const [items, setItems] = React.useState<OwnerNotificationRecord[]>([]);
  const [loading, setLoading] = React.useState(false);

  const sortKey = (item: OwnerNotificationRecord): [number, string] => [
    item.created_at_ms,
    item.notification_id,
  ];
  const position =
    result?.status === "ok" ? nextPosition(result.data, sortKey) : null;

  const load = React.useCallback(
    async (more: boolean) => {
      setLoading(true);
      try {
        const next = await readOwnerNotifications(more ? position : null);
        setResult(next);
        setItems((previous) =>
          next.status === "ok"
            ? [...(more ? previous : []), ...next.data.items]
            : [],
        );
      } catch (error) {
        toast.error(`Notifications not read: ${errorText(error)}`);
      } finally {
        setLoading(false);
      }
    },
    [position],
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Button
          disabled={loading}
          onClick={() => void load(false)}
          size="sm"
          type="button"
          variant="outline"
        >
          {result ? "Reload" : "Show owner notifications"}
        </Button>
      </div>
      {result?.status === "not_granted" ? (
        <p className="text-sm text-muted-foreground">
          Your access does not include notifications.
        </p>
      ) : null}
      {result?.status === "error" ? (
        <p className="text-sm text-muted-foreground">
          {readErrorLabel(result.code)}
        </p>
      ) : null}
      {result?.status === "ok" && items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No notifications.</p>
      ) : null}
      {items.length > 0 ? (
        <ul className="space-y-2" data-testid="owner-notifications">
          {items.map((item) => (
            <Notification
              item={item}
              key={item.notification_id}
              names={names}
            />
          ))}
        </ul>
      ) : null}
      {position ? (
        <Button
          disabled={loading}
          onClick={() => void load(true)}
          size="sm"
          type="button"
          variant="outline"
        >
          Show more
        </Button>
      ) : null}
    </div>
  );
}

export function BehaviorAccessSettingsCard() {
  const [status, setStatus] = React.useState<BehaviorBindingStatus | null>(
    null,
  );
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    getBehaviorBindingStatus()
      .then(setStatus)
      .catch(() => setStatus({ state: "invalid" }));
  }, []);

  const run = async (
    action: () => Promise<BehaviorBindingStatus>,
    done?: string,
  ) => {
    setBusy(true);
    try {
      setStatus(await action());
      if (done) {
        toast.success(done);
      }
    } catch (error) {
      toast.error(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const names = React.useMemo(
    () =>
      new Map(
        status?.state === "active"
          ? status.subjects.map((subject) => [
              subject.subject_agent_id,
              subject.domain,
            ])
          : [],
      ),
    [status],
  );
  const hasBinding = status !== null && status.state !== "none";

  return (
    <section className="min-w-0" data-testid="settings-behavior-access">
      <SettingsSectionHeader
        title="Agent behavior"
        description="Read what your owner service reports about other agents: behavior standing, blocked attempts, notifications and recovery. Buzz only shows these records."
      />
      <SettingsOptionGroup>
        <SettingsOptionRow>
          <div className="min-w-0">
            <p className="text-sm font-medium">Owner read access</p>
            <p className="text-sm font-normal text-muted-foreground">
              {statusText(status)}
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <Button
              disabled={busy}
              onClick={() => void run(importBehaviorBinding)}
              size="sm"
              type="button"
              variant="outline"
            >
              {hasBinding ? "Replace" : "Set up"}
            </Button>
            {hasBinding ? (
              <Button
                disabled={busy}
                onClick={() =>
                  void run(
                    removeBehaviorBinding,
                    "Removed from this device. Ask the owner to revoke the token too.",
                  )
                }
                size="sm"
                type="button"
                variant="outline"
              >
                Remove
              </Button>
            ) : null}
          </div>
        </SettingsOptionRow>
        {status?.state === "active" &&
        status.scopes.includes("notifications:read") ? (
          <SettingsOptionRow>
            <div className="min-w-0 flex-1">
              <NotificationsList names={names} />
            </div>
          </SettingsOptionRow>
        ) : null}
      </SettingsOptionGroup>
    </section>
  );
}
