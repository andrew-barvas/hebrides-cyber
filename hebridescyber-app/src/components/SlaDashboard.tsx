"use client";

import { useCallback, useEffect, useId, useState } from "react";
import LockedFeature from "@/components/LockedFeature";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input, Label } from "@/components/ui/input";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { Skeleton } from "@/components/ui/skeleton";
import { StatCard } from "@/components/ui/stat-card";
import { SLA_SEVERITIES, type SlaItem, type SlaPolicy, type SlaSeverity, type SlaSummary } from "@/lib/slaMonitoring";
import { cn } from "@/lib/utils";

type SlaResponse = {
  access: boolean;
  available: boolean;
  policy: SlaPolicy;
  resolvedWindowDays?: number;
  summary: (SlaSummary & { truncated: boolean }) | null;
};

type Filter = "all" | "breached" | "due_soon";

const SEVERITY_LABEL: Record<SlaSeverity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

function remainingText(item: SlaItem) {
  const days = Math.round(Math.abs(item.daysRemaining));
  if (item.state === "breached") return days === 0 ? "Overdue today" : `${days} day${days === 1 ? "" : "s"} overdue`;
  if (days === 0) return "Due today";
  return item.state === "due_soon" ? `Due in ${days} day${days === 1 ? "" : "s"}` : `${days} days left`;
}

const STATE_CLASS = { breached: "text-danger", due_soon: "text-warning", on_track: "text-cybermuted" } as const;

function PolicyForm({ policy, token, onSaved }: { policy: SlaPolicy; token: string | null; onSaved: () => void }) {
  const id = useId();
  const [days, setDays] = useState<Record<SlaSeverity, string>>(
    Object.fromEntries(SLA_SEVERITIES.map((s) => [s, String(policy.days[s])])) as Record<SlaSeverity, string>
  );
  const [warnDays, setWarnDays] = useState(String(policy.warnDays));
  const [alertsEnabled, setAlertsEnabled] = useState(policy.alertsEnabled);
  const [status, setStatus] = useState<{ kind: "idle" | "saving" | "saved" } | { kind: "error"; message: string }>({ kind: "idle" });

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    setStatus({ kind: "saving" });
    try {
      const res = await fetch("/api/account/sla", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          days: Object.fromEntries(SLA_SEVERITIES.map((s) => [s, Number(days[s])])),
          warnDays: Number(warnDays),
          alertsEnabled,
        }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not save your targets");
      setStatus({ kind: "saved" });
      onSaved();
    } catch (err) {
      setStatus({ kind: "error", message: (err as Error).message });
    }
  }

  return (
    <Card>
      <CardTitle>targets</CardTitle>
      <CardDescription className="mt-1">
        Days allowed to fix a finding, counted from when a scan first found it. Informational findings carry no SLA. The
        defaults follow CISA BOD 19-02 for critical and high.
      </CardDescription>
      <form onSubmit={save} className="mt-4 space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {SLA_SEVERITIES.map((s) => (
            <div key={s} className="space-y-1.5">
              <Label htmlFor={`${id}-${s}`}>{SEVERITY_LABEL[s]} (days)</Label>
              <Input
                id={`${id}-${s}`}
                type="number"
                inputMode="numeric"
                min={1}
                max={365}
                required
                value={days[s]}
                onChange={(e) => setDays((d) => ({ ...d, [s]: e.target.value }))}
              />
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-end gap-6">
          <div className="space-y-1.5">
            <Label htmlFor={`${id}-warn`}>Warn this many days before</Label>
            <Input
              id={`${id}-warn`}
              type="number"
              inputMode="numeric"
              min={0}
              max={30}
              required
              value={warnDays}
              onChange={(e) => setWarnDays(e.target.value)}
              className="w-28"
            />
          </div>
          <label className="flex items-center gap-2 pb-2 text-sm text-cybertext">
            <input type="checkbox" checked={alertsEnabled} onChange={(e) => setAlertsEnabled(e.target.checked)} className="size-4 accent-neon" />
            Email me when a finding nears or passes its SLA
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!token || status.kind === "saving"}>
            {status.kind === "saving" ? "Saving…" : "Save targets"}
          </Button>
          {status.kind === "saved" && (
            <p role="status" className="text-sm text-neon">
              Saved.
            </p>
          )}
          {status.kind === "error" && (
            <p role="alert" className="text-sm text-danger">
              {status.message}
            </p>
          )}
        </div>
      </form>
    </Card>
  );
}

async function fetchSla(token: string): Promise<SlaResponse> {
  const res = await fetch("/api/account/sla", { headers: { Authorization: `Bearer ${token}` } });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? "Could not load SLA status");
  return body;
}

export default function SlaDashboard({ token }: { token: string | null }) {
  const [data, setData] = useState<SlaResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");

  const load = useCallback(() => {
    if (!token) return;
    fetchSla(token).then(
      (body) => {
        setData(body);
        setError(null);
      },
      (err: Error) => setError(err.message)
    );
  }, [token]);

  useEffect(load, [load]);

  if (error) return <Alert variant="danger" title="Couldn't load remediation SLAs">{error}</Alert>;
  if (!data) return <Skeleton className="h-48 w-full rounded-xl" />;

  if (!data.access) {
    return (
      <LockedFeature
        title="remediation SLAs"
        description="Set fix-by targets per severity, see every open finding's deadline across your client sites, track time-to-fix, and get an email before a site breaches."
        availableOn="Agency"
      />
    );
  }

  if (!data.available || !data.summary) {
    return (
      <Alert variant="warning" title="SLA tracking isn't switched on yet">
        This server&apos;s database is missing the SLA tables (migration 043). Once they&apos;re in place, the next scan
        of each site starts tracking, dating existing findings from up to 45 earlier scans.
      </Alert>
    );
  }

  const { summary, policy } = data;
  const items = filter === "all" ? summary.items : summary.items.filter((i) => i.state === filter);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Open with an SLA" value={summary.open} />
        <StatCard label="On track" value={summary.onTrack} tone="brand" />
        <StatCard label="Due soon" value={summary.dueSoon} tone={summary.dueSoon ? "warning" : "muted"} hint={`Within ${policy.warnDays} days`} />
        <StatCard label="Breached" value={summary.breached} tone={summary.breached ? "danger" : "muted"} />
      </div>

      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>open findings</CardTitle>
            <CardDescription className="mt-1">Most urgent first. Clocks start when a scan first finds the issue.</CardDescription>
          </div>
          <SegmentedControl
            aria-label="Filter by SLA status"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: `All (${summary.open})` },
              { value: "breached", label: `Breached (${summary.breached})` },
              { value: "due_soon", label: `Due soon (${summary.dueSoon})` },
            ]}
          />
        </div>

        {items.length === 0 ? (
          <EmptyState
            as="h3"
            className="mt-4"
            title={summary.open === 0 ? "Nothing open against an SLA" : "Nothing in this view"}
            description={
              summary.open === 0
                ? "Every finding with a severity rating is either fixed or informational."
                : "Switch the filter to see the rest."
            }
          />
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <caption className="sr-only">Open findings and their remediation deadlines</caption>
              <thead>
                <tr className="border-b border-cyberborder font-mono text-[11px] uppercase tracking-wider text-cybermuted">
                  <th scope="col" className="py-2 pr-4 font-medium">Finding</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Site</th>
                  <th scope="col" className="py-2 pr-4 font-medium">First seen</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Due</th>
                  <th scope="col" className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyberborder">
                {items.map((item) => (
                  <tr key={item.id}>
                    <td className="py-2.5 pr-4">
                      <span className="mr-2 font-mono text-[11px] uppercase text-cybermuted">{item.severity}</span>
                      <span className="text-cybertext">{item.title}</span>
                    </td>
                    <td className="py-2.5 pr-4 text-cybermuted">{item.host}</td>
                    <td className="py-2.5 pr-4 tabular-nums text-cybermuted">{formatDate(item.firstSeenAt)}</td>
                    <td className="py-2.5 pr-4 tabular-nums text-cybermuted">{formatDate(item.dueAt)}</td>
                    <td className={cn("py-2.5 font-medium tabular-nums", STATE_CLASS[item.state])}>{remainingText(item)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {summary.truncated && <p className="mt-2 text-xs text-cybermuted">Showing the 500 most urgent.</p>}
          </div>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardTitle>by site</CardTitle>
          {summary.hosts.length === 0 ? (
            <CardDescription className="mt-2">No open findings on any site.</CardDescription>
          ) : (
            <ul className="mt-3 divide-y divide-cyberborder text-sm">
              {summary.hosts.map((h) => (
                <li key={h.host} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <span className="break-all text-cybertext">{h.host}</span>
                  <span className="tabular-nums text-cybermuted">
                    {h.open} open
                    {h.dueSoon > 0 && <span className="text-warning"> · {h.dueSoon} due soon</span>}
                    {h.breached > 0 && <span className="text-danger"> · {h.breached} breached</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardTitle>time to fix</CardTitle>
          <CardDescription className="mt-1">Findings resolved in the last {data.resolvedWindowDays ?? 90} days.</CardDescription>
          <table className="mt-3 w-full text-left text-sm">
            <thead>
              <tr className="border-b border-cyberborder font-mono text-[11px] uppercase tracking-wider text-cybermuted">
                <th scope="col" className="py-2 pr-3 font-medium">Severity</th>
                <th scope="col" className="py-2 pr-3 font-medium">Target</th>
                <th scope="col" className="py-2 pr-3 font-medium">Fixed</th>
                <th scope="col" className="py-2 pr-3 font-medium">Median</th>
                <th scope="col" className="py-2 font-medium">In SLA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyberborder tabular-nums">
              {SLA_SEVERITIES.map((s) => {
                const r = summary.resolved[s];
                return (
                  <tr key={s}>
                    <th scope="row" className="py-2 pr-3 font-medium text-cybertext">{SEVERITY_LABEL[s]}</th>
                    <td className="py-2 pr-3 text-cybermuted">{policy.days[s]}d</td>
                    <td className="py-2 pr-3 text-cybermuted">{r.count}</td>
                    <td className="py-2 pr-3 text-cybermuted">{r.medianDaysToFix === null ? "—" : `${Math.round(r.medianDaysToFix * 10) / 10}d`}</td>
                    <td className="py-2 text-cybermuted">{r.count === 0 ? "—" : `${Math.round((r.withinSla / r.count) * 100)}%`}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      </div>

      {/* Re-fetch after saving: every deadline above moves with the targets. */}
      <PolicyForm policy={policy} token={token} onSaved={load} />
    </div>
  );
}
