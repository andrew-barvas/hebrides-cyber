"use client";

// The cross-site findings view (E-74): every open finding across all sites,
// filterable, groupable by check ("missing HSTS on 7 sites") with multi-select
// and bulk triage. Data comes from GET /api/findings; triage is written
// through the existing bulk PUT /api/findings/triage — this component never
// decides what a triage state means (src/lib/findingTriage.ts does).
//
// Types only from findingsView.ts: its loader is server code.
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/input";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { SNOOZE_PRESET_DAYS, TRIAGE_BULK_MAX, TRIAGE_REASON_MAX, TRIAGE_REASON_MIN, TRIAGE_STATE_LABELS, reasonLength } from "@/lib/findingTriage";
import type { Facets, FindingGroup, FindingRow, FindingSeverity } from "@/lib/findingsView";
import { cn } from "@/lib/utils";

type ViewMode = "grouped" | "rows";

type FindingsResponse = {
  available: boolean;
  triageAvailable: boolean;
  slaEnabled: boolean;
  detailComplete: boolean;
  truncated: boolean;
  facets: Facets;
  view: ViewMode;
  totalFindings: number;
  items: FindingRow[];
  groups: FindingGroup[];
  page: number;
  pageSize: number;
  total: number;
  pageCount: number;
};

type Filters = {
  site: string;
  severity: "" | FindingSeverity;
  kev: boolean;
  epssMin: string;
  category: string;
  triage: string;
  sla: string;
  minAgeDays: string;
};

const DEFAULT_FILTERS: Filters = { site: "", severity: "", kev: false, epssMin: "", category: "", triage: "open", sla: "", minAgeDays: "" };

const SEVERITY_OPTIONS: ReadonlyArray<{ value: "" | FindingSeverity; label: string }> = [
  { value: "", label: "Any severity" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const SEVERITY_CLASS: Record<FindingSeverity, string> = {
  critical: "border-danger/40 text-danger",
  high: "border-danger/40 text-danger",
  medium: "border-warning/40 text-warning",
  low: "border-cyberborder text-cybermuted",
  info: "border-cyberborder text-cybermuted",
};

const SLA_LABEL = { breached: "SLA breached", due_soon: "SLA due soon", on_track: "On track" } as const;

type BulkChoice = "accepted_risk" | "false_positive" | "snoozed";

const BULK_ACTIONS: ReadonlyArray<{ value: BulkChoice; label: string }> = [
  { value: "accepted_risk", label: "Accept / authorise" },
  { value: "false_positive", label: "False positive" },
  { value: "snoozed", label: "Snooze" },
];

const DAY_MS = 24 * 60 * 60 * 1000;

const SELECT_CLASS =
  "h-10 w-full rounded-md border border-cyberborder bg-cyberbg px-3 text-sm text-cybertext focus-visible:border-neon focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-neon/40";

function buildQuery(filters: Filters, view: ViewMode, page: number, format?: "csv"): string {
  const p = new URLSearchParams();
  if (filters.site) p.set("site", filters.site);
  if (filters.severity) p.set("severity", filters.severity);
  if (filters.kev) p.set("kev", "1");
  if (filters.epssMin) p.set("epssMin", filters.epssMin);
  if (filters.category) p.set("category", filters.category);
  p.set("triage", filters.triage);
  if (filters.sla) p.set("sla", filters.sla);
  if (filters.minAgeDays) p.set("minAgeDays", filters.minAgeDays);
  if (format) {
    p.set("format", format);
  } else {
    p.set("view", view);
    p.set("page", String(page));
  }
  return p.toString();
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: ReadonlyArray<{ value: string; label: string }>;
}) {
  const id = useId();
  return (
    <div className="min-w-36 flex-1 space-y-1.5">
      <Label htmlFor={id} className="text-xs text-cybermuted">
        {label}
      </Label>
      <select id={id} className={SELECT_CLASS} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span className={cn("rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase", SEVERITY_CLASS[severity])}>{severity}</span>
  );
}

function Flags({ row }: { row: Pick<FindingRow, "knownExploited" | "ransomware" | "epss"> }) {
  return (
    <>
      {row.knownExploited && (
        <span className="rounded-sm border border-danger/40 px-1.5 py-0.5 text-[11px] font-semibold text-danger">
          {row.ransomware ? "Known exploited · ransomware" : "Known exploited"}
        </span>
      )}
      {row.epss !== null && (
        <span className="rounded-sm border border-cyberborder px-1.5 py-0.5 text-[11px] text-cybermuted">EPSS {Math.round(row.epss * 100)}%</span>
      )}
    </>
  );
}

function FindingLine({
  row,
  checked,
  onToggle,
  showTitle,
}: {
  row: FindingRow;
  checked: boolean;
  onToggle: () => void;
  showTitle: boolean;
}) {
  const id = useId();
  return (
    <li className="flex items-start gap-3 py-2">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        aria-label={`Select ${row.title} on ${row.host}`}
        className="mt-1 size-4 shrink-0 accent-neon"
      />
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          {showTitle && <SeverityBadge severity={row.severity} />}
          <span className="break-all text-sm font-medium text-cybertext">{showTitle ? row.title : row.host}</span>
          <Flags row={row} />
          {row.triage && (
            <span className="rounded-sm border border-neon/30 px-1.5 py-0.5 text-[11px] text-neon">{TRIAGE_STATE_LABELS[row.triage.state]}</span>
          )}
        </div>
        <p className="break-all text-xs text-cybermuted">
          {showTitle && <>{row.host} · </>}
          {row.checkId} · open {row.ageDays} day{row.ageDays === 1 ? "" : "s"}
          {row.slaState && <> · {SLA_LABEL[row.slaState]}</>}
          {row.scanId && (
            <>
              {" · "}
              <a href={`/dashboard/scans/${row.scanId}`} className="text-neon hover:underline">
                Latest report<span className="sr-only"> for {row.host}</span>
              </a>
            </>
          )}
        </p>
        {row.triage && <p className="text-xs text-cybermuted">Reason: {row.triage.reason}</p>}
      </div>
    </li>
  );
}

function GroupCard({
  group,
  selected,
  onToggleRow,
  onToggleGroup,
}: {
  group: FindingGroup;
  selected: ReadonlySet<string>;
  onToggleRow: (key: string) => void;
  onToggleGroup: (group: FindingGroup) => void;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const chosen = group.rows.filter((r) => selected.has(r.key)).length;
  const all = chosen === group.rows.length;
  const checkboxRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (checkboxRef.current) checkboxRef.current.indeterminate = chosen > 0 && !all;
  }, [chosen, all]);

  return (
    <Card className="space-y-2">
      <div className="flex items-start gap-3">
        <input
          ref={checkboxRef}
          type="checkbox"
          checked={all}
          onChange={() => onToggleGroup(group)}
          aria-label={`Select all ${group.count} findings for ${group.label}`}
          className="mt-1 size-4 shrink-0 accent-neon"
        />
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={group.severity} />
            <h3 className="text-sm font-semibold text-cybertext">{group.label}</h3>
            <Flags row={{ knownExploited: group.knownExploited, ransomware: false, epss: group.maxEpss }} />
          </div>
          <p className="text-xs text-cybermuted">
            {group.siteCount === 1 ? `On ${group.sites[0]}` : `On ${group.siteCount} sites`} · {group.count} finding{group.count === 1 ? "" : "s"} ·{" "}
            {group.category}
          </p>
        </div>
        <Button variant="ghost" size="sm" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Show"}
          <span className="sr-only"> {group.count} findings for {group.label}</span>
        </Button>
      </div>
      {open && (
        <ul id={panelId} className="divide-y divide-cyberborder border-t border-cyberborder pl-7">
          {group.rows.map((r) => (
            <FindingLine key={r.key} row={r} checked={selected.has(r.key)} onToggle={() => onToggleRow(r.key)} showTitle={false} />
          ))}
        </ul>
      )}
    </Card>
  );
}

type BulkStatus = { kind: "idle" } | { kind: "saving" } | { kind: "error"; message: string } | { kind: "done"; message: string };

function BulkBar({
  count,
  disabled,
  status,
  onApply,
  onClear,
}: {
  count: number;
  disabled: boolean;
  status: BulkStatus;
  onApply: (choice: BulkChoice, reason: string, snoozeDays: number) => void;
  onClear: () => void;
}) {
  const id = useId();
  const [choice, setChoice] = useState<BulkChoice | null>(null);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState<number>(SNOOZE_PRESET_DAYS[1]);
  const length = reasonLength(reason.trim());
  const reasonOk = length >= TRIAGE_REASON_MIN && length <= TRIAGE_REASON_MAX;
  const saving = status.kind === "saving";

  if (count === 0) return null;
  return (
    <Card className="sticky bottom-4 z-10 space-y-3 shadow-glowsm">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-sm font-medium text-cybertext" role="status">
          {count} finding{count === 1 ? "" : "s"} selected
        </p>
        {BULK_ACTIONS.map((a) => (
          <Button
            key={a.value}
            size="sm"
            variant={choice === a.value ? "primary" : "secondary"}
            aria-pressed={choice === a.value}
            disabled={disabled || saving}
            onClick={() => setChoice(choice === a.value ? null : a.value)}
          >
            {a.label}
          </Button>
        ))}
        <Button size="sm" variant="ghost" onClick={onClear} disabled={saving}>
          Clear selection
        </Button>
      </div>
      {disabled && <p className="text-xs text-cybermuted">Triage isn&apos;t enabled on this server yet.</p>}
      {choice && !disabled && (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (reasonOk) onApply(choice, reason.trim(), days);
          }}
        >
          <p className="text-xs text-cybermuted">
            {choice === "accepted_risk" && "Takes the selected findings out of your open list and SLAs. Use it to authorise a third-party script too. They still count towards the score."}
            {choice === "false_positive" && "Not a real issue. The findings leave your open list and SLAs, and stop counting towards the score from the next scan."}
            {choice === "snoozed" && "Hidden until the date, then back in your open list with their original SLA deadline."}
          </p>
          {choice === "snoozed" && (
            <div className="max-w-xs space-y-1.5">
              <Label htmlFor={`${id}-days`}>Snooze for</Label>
              <select id={`${id}-days`} className={SELECT_CLASS} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {SNOOZE_PRESET_DAYS.map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="space-y-1.5">
            <Label htmlFor={`${id}-reason`}>Reason (recorded in your audit log)</Label>
            <Textarea
              id={`${id}-reason`}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={TRIAGE_REASON_MAX}
              aria-describedby={`${id}-hint`}
              aria-invalid={reason.length > 0 && !reasonOk}
            />
            <p id={`${id}-hint`} className="text-xs text-cybermuted">
              At least {TRIAGE_REASON_MIN} characters.
            </p>
          </div>
          <Button type="submit" size="sm" disabled={!reasonOk || saving}>
            {saving ? "Saving…" : `Apply to ${count} finding${count === 1 ? "" : "s"}`}
          </Button>
        </form>
      )}
      {status.kind === "error" && <Alert variant="danger">{status.message}</Alert>}
    </Card>
  );
}

export default function FindingsExplorer({ token }: { token: string | null }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [view, setView] = useState<ViewMode>("grouped");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [bulk, setBulk] = useState<BulkStatus>({ kind: "idle" });
  const [exportError, setExportError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    fetch(`/api/findings?${buildQuery(filters, view, page)}`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal })
      .then(async (res) => {
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error ?? "Could not load your findings");
        setData(body as FindingsResponse);
        // The server clamps a page past the end; follow it.
        if (typeof body.page === "number" && body.page !== page) setPage(body.page);
      })
      .catch((err: Error) => {
        if (err.name !== "AbortError") setError(err.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [token, filters, view, page, reloads]);

  const rowsOnPage = useMemo(() => (data ? (data.view === "grouped" ? data.groups.flatMap((g) => g.rows) : data.items) : []), [data]);
  const byKey = useMemo(() => new Map(rowsOnPage.map((r) => [r.key, r])), [rowsOnPage]);

  function updateFilter<K extends keyof Filters>(name: K, value: Filters[K]) {
    setFilters((f) => ({ ...f, [name]: value }));
    setPage(1);
    setSelected(new Set());
    setBulk({ kind: "idle" });
  }

  const toggleRow = useCallback((key: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }, []);

  const toggleGroup = useCallback((group: FindingGroup) => {
    setSelected((prev) => {
      const next = new Set(prev);
      const all = group.rows.every((r) => next.has(r.key));
      for (const r of group.rows) {
        if (all) next.delete(r.key);
        else next.add(r.key);
      }
      return next;
    });
  }, []);

  async function applyBulk(choice: BulkChoice, reason: string, snoozeDays: number) {
    if (!token) return;
    const rows = [...selected].map((k) => byKey.get(k)).filter((r): r is FindingRow => Boolean(r));
    const expiresAt = choice === "snoozed" ? new Date(Date.now() + snoozeDays * DAY_MS).toISOString() : null;
    setBulk({ kind: "saving" });
    try {
      for (let i = 0; i < rows.length; i += TRIAGE_BULK_MAX) {
        const items = rows.slice(i, i + TRIAGE_BULK_MAX).map((r) => ({ targetHost: r.host, checkId: r.checkId, state: choice, reason, expiresAt }));
        const res = await fetch("/api/findings/triage", {
          method: "PUT",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ items }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error ?? "Could not save the triage");
      }
      setSelected(new Set());
      setBulk({ kind: "done", message: `${rows.length} finding${rows.length === 1 ? "" : "s"} marked as ${TRIAGE_STATE_LABELS[choice].toLowerCase()}.` });
      setReloads((n) => n + 1);
    } catch (err) {
      setBulk({ kind: "error", message: (err as Error).message });
    }
  }

  async function exportCsv() {
    if (!token) return;
    setExportError(null);
    try {
      const res = await fetch(`/api/findings?${buildQuery(filters, view, page, "csv")}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error("Could not export your findings");
      const url = URL.createObjectURL(await res.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "open-findings.csv";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError((err as Error).message);
    }
  }

  const facets = data?.facets;
  const filtersActive = JSON.stringify(filters) !== JSON.stringify(DEFAULT_FILTERS);

  return (
    <div className="space-y-4">
      <section aria-label="Filters" className="space-y-3">
        <div className="flex flex-wrap gap-3">
          <FilterSelect
            label="Site"
            value={filters.site}
            onChange={(v) => updateFilter("site", v)}
            options={[{ value: "", label: "All sites" }, ...(facets?.sites ?? []).map((s) => ({ value: s.value, label: `${s.value} (${s.count})` }))]}
          />
          <FilterSelect label="Severity" value={filters.severity} onChange={(v) => updateFilter("severity", v as Filters["severity"])} options={SEVERITY_OPTIONS} />
          <FilterSelect
            label="Category"
            value={filters.category}
            onChange={(v) => updateFilter("category", v)}
            options={[{ value: "", label: "All categories" }, ...(facets?.categories ?? []).map((c) => ({ value: c.value, label: `${c.value} (${c.count})` }))]}
          />
          <FilterSelect
            label="Triage"
            value={filters.triage}
            onChange={(v) => updateFilter("triage", v)}
            options={[
              { value: "open", label: "Not triaged" },
              { value: "triaged", label: "Any triage" },
              { value: "accepted_risk", label: TRIAGE_STATE_LABELS.accepted_risk },
              { value: "false_positive", label: TRIAGE_STATE_LABELS.false_positive },
              { value: "snoozed", label: TRIAGE_STATE_LABELS.snoozed },
              { value: "all", label: "Everything" },
            ]}
          />
          <FilterSelect
            label="Exploit likelihood (EPSS)"
            value={filters.epssMin}
            onChange={(v) => updateFilter("epssMin", v)}
            options={[
              { value: "", label: "Any" },
              { value: "0.1", label: "10% or more" },
              { value: "0.5", label: "50% or more" },
            ]}
          />
          <FilterSelect
            label="Open for"
            value={filters.minAgeDays}
            onChange={(v) => updateFilter("minAgeDays", v)}
            options={[
              { value: "", label: "Any time" },
              { value: "7", label: "7+ days" },
              { value: "30", label: "30+ days" },
              { value: "90", label: "90+ days" },
            ]}
          />
          {data?.slaEnabled && (
            <FilterSelect
              label="SLA"
              value={filters.sla}
              onChange={(v) => updateFilter("sla", v)}
              options={[
                { value: "", label: "Any" },
                { value: "breached", label: "Breached" },
                { value: "due_soon", label: "Due soon" },
                { value: "on_track", label: "On track" },
              ]}
            />
          )}
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-cybertext">
            <input
              type="checkbox"
              checked={filters.kev}
              onChange={(e) => updateFilter("kev", e.target.checked)}
              className="size-4 accent-neon"
            />
            Known exploited (CISA KEV) only
          </label>
          <SegmentedControl<ViewMode>
            aria-label="Group findings"
            value={view}
            onChange={(v) => {
              setView(v);
              setPage(1);
              setSelected(new Set());
            }}
            options={[
              { value: "grouped", label: "Grouped by check" },
              { value: "rows", label: "All findings" },
            ]}
          />
          {filtersActive && (
            <Button variant="ghost" size="sm" onClick={() => { setFilters(DEFAULT_FILTERS); setPage(1); setSelected(new Set()); }}>
              Reset filters
            </Button>
          )}
          <Button variant="secondary" size="sm" className="ml-auto" onClick={exportCsv} disabled={!data || data.totalFindings === 0}>
            <Download aria-hidden="true" />
            Export CSV
          </Button>
        </div>
      </section>

      {exportError && <Alert variant="danger">{exportError}</Alert>}
      {bulk.kind === "done" && <Alert variant="success">{bulk.message}</Alert>}
      {data && !data.detailComplete && (
        <Alert variant="warning" title="Some detail is missing">
          Exploit data (KEV / EPSS) couldn&apos;t be read from your latest scans, so those filters may miss findings.
        </Alert>
      )}
      {data?.truncated && (
        <Alert variant="warning" title="Showing part of your findings">
          You have more open findings than one view can hold. Filter by site to see the rest.
        </Alert>
      )}

      {error && (
        <Alert variant="danger" title="Couldn't load findings">
          {error}{" "}
          <Button size="sm" variant="secondary" onClick={() => setReloads((n) => n + 1)}>
            Try again
          </Button>
        </Alert>
      )}

      {loading && !data && !error && (
        <div className="space-y-3" role="status" aria-label="Loading findings">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}

      {data && !data.available && (
        <EmptyState
          icon={<ShieldCheck />}
          title="Finding tracking isn't switched on yet"
          description="This view needs the finding-lifecycle database migration (043). Once it's applied, your open findings appear here after the next scan."
        />
      )}

      {data && data.available && data.totalFindings === 0 && !error && (
        <EmptyState
          icon={<ShieldCheck />}
          title={filtersActive ? "No findings match these filters" : "No open findings"}
          description={filtersActive ? "Try widening or resetting the filters." : "Nothing is open across your sites. New findings show up here after each scan."}
        />
      )}

      {data && data.available && data.totalFindings > 0 && (
        <div className={cn("space-y-3", loading && "opacity-60")} aria-busy={loading}>
          <p className="text-sm text-cybermuted" aria-live="polite">
            {data.totalFindings} finding{data.totalFindings === 1 ? "" : "s"}
            {data.view === "grouped" && ` in ${data.total} group${data.total === 1 ? "" : "s"}`}
          </p>
          {data.view === "grouped" ? (
            data.groups.map((g) => <GroupCard key={g.key} group={g} selected={selected} onToggleRow={toggleRow} onToggleGroup={toggleGroup} />)
          ) : (
            <Card>
              <ul className="divide-y divide-cyberborder" aria-label="Open findings">
                {data.items.map((r) => (
                  <FindingLine key={r.key} row={r} checked={selected.has(r.key)} onToggle={() => toggleRow(r.key)} showTitle />
                ))}
              </ul>
            </Card>
          )}
          {data.pageCount > 1 && (
            <nav aria-label="Pagination" className="flex items-center justify-between gap-3">
              <Button variant="secondary" size="sm" disabled={data.page <= 1} onClick={() => { setPage(data.page - 1); setSelected(new Set()); }}>
                Previous
              </Button>
              <p className="text-sm text-cybermuted">
                Page {data.page} of {data.pageCount}
              </p>
              <Button variant="secondary" size="sm" disabled={data.page >= data.pageCount} onClick={() => { setPage(data.page + 1); setSelected(new Set()); }}>
                Next
              </Button>
            </nav>
          )}
        </div>
      )}

      <BulkBar
        count={selected.size}
        disabled={Boolean(data && !data.triageAvailable)}
        status={bulk}
        onApply={applyBulk}
        onClear={() => setSelected(new Set())}
      />
    </div>
  );
}
