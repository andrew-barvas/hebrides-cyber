"use client";

// Per-finding triage controls for the scan report (E-64): "Mark as…"
// (accepted / authorised, false positive, snooze 7/30/90 days — always with
// a reason) and Undo. Both call /api/findings/triage with the scan id, so the
// decision applies to this finding on this site from now on, not just to
// this one report. What each state does lives in src/lib/findingTriage.ts.
//
// Deliberately free of ScanReportView imports — ScanReportView renders these.
import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/input";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { Textarea } from "@/components/ui/textarea";
import {
  SNOOZE_PRESET_DAYS,
  TRIAGE_REASON_MAX,
  TRIAGE_REASON_MIN,
  TRIAGE_STATE_LABELS,
  reasonLength,
  type TriageRecord,
  type TriageState,
} from "@/lib/findingTriage";

/** A finding's active triage, as the report renders it. */
export type ViewTriage = {
  state: TriageState;
  reason: string;
  expiresAt: string | null;
  triagedAt: string;
  triagedByEmail?: string | null;
};

export function viewTriageFrom(record: TriageRecord): ViewTriage {
  return {
    state: record.state,
    reason: record.reason,
    expiresAt: record.expiresAt,
    triagedAt: record.triagedAt,
    triagedByEmail: record.triagedByEmail,
  };
}

type SnoozeChoice = `snooze-${(typeof SNOOZE_PRESET_DAYS)[number]}`;
export type TriageChoice = "accepted_risk" | "false_positive" | SnoozeChoice;

const CHOICES: ReadonlyArray<{ value: TriageChoice; label: string }> = [
  { value: "accepted_risk", label: TRIAGE_STATE_LABELS.accepted_risk },
  { value: "false_positive", label: TRIAGE_STATE_LABELS.false_positive },
  ...SNOOZE_PRESET_DAYS.map((days) => ({ value: `snooze-${days}` as SnoozeChoice, label: `Snooze ${days} days` })),
];

const CHOICE_HINT: Record<TriageState, string> = {
  accepted_risk:
    "You know about this and accept it — or, for a third-party script, have authorised it. It leaves your open findings and SLA tracking, but still counts towards your score: the risk is still there.",
  false_positive: "Not a real issue on this site. It leaves your open findings and SLA tracking, and from the next scan it no longer counts towards your score.",
  snoozed:
    "Hidden until the date below, then back in your open findings with its original SLA deadline. Still counts towards your score.",
};

const DAY_MS = 24 * 60 * 60 * 1000;

/** The state and expiry a menu choice stands for, as of `now`. */
export function triagePayloadFor(choice: TriageChoice, now: Date): { state: TriageState; expiresAt: string | null } {
  if (choice.startsWith("snooze-")) {
    const days = Number(choice.slice("snooze-".length));
    return { state: "snoozed", expiresAt: new Date(now.getTime() + days * DAY_MS).toISOString() };
  }
  return { state: choice as TriageState, expiresAt: null };
}

export function formatTriageDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

/** "Snoozed by sam@… on 3 Oct 2026 · until 2 Nov 2026" */
export function describeTriage(triage: ViewTriage): string {
  const who = triage.triagedByEmail ? ` by ${triage.triagedByEmail}` : "";
  const until = triage.expiresAt ? ` · until ${formatTriageDate(triage.expiresAt)}` : " · no expiry";
  return `${TRIAGE_STATE_LABELS[triage.state]}${who} on ${formatTriageDate(triage.triagedAt)}${until}`;
}

async function callTriageApi(method: "PUT" | "DELETE", token: string, body: Record<string, unknown>) {
  const res = await fetch("/api/findings/triage", {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error ?? `Request failed (${res.status})`);
  return json;
}

export function TriageMenu({
  scanId,
  token,
  checkId,
  onTriaged,
}: {
  scanId: string;
  token: string;
  checkId: string;
  onTriaged: (triage: ViewTriage) => void;
}) {
  const reasonId = useId();
  const hintId = useId();
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<TriageChoice>("accepted_risk");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const length = reasonLength(reason.trim());
  const reasonOk = length >= TRIAGE_REASON_MIN && length <= TRIAGE_REASON_MAX;
  const { state } = triagePayloadFor(choice, new Date());

  function close() {
    setOpen(false);
    setReason("");
    setError(null);
    setChoice("accepted_risk");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!reasonOk || saving) return;
    setSaving(true);
    setError(null);
    try {
      const payload = triagePayloadFor(choice, new Date());
      const body = await callTriageApi("PUT", token, { scanId, checkId, reason: reason.trim(), ...payload });
      onTriaged(viewTriageFrom(body.item as TriageRecord));
      close();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (!open) {
    return (
      <Button variant="ghost" size="sm" className="mt-3 print:hidden" aria-expanded={false} onClick={() => setOpen(true)}>
        Mark as…
      </Button>
    );
  }

  return (
    <form onSubmit={submit} className="mt-3 space-y-3 rounded-lg border border-cyberborder bg-cyberpanel p-3 print:hidden">
      <SegmentedControl aria-label="Mark this finding as" value={choice} onChange={setChoice} options={CHOICES} />
      <p id={hintId} className="text-xs text-cybermuted">
        {CHOICE_HINT[state]}
      </p>
      <div className="space-y-1">
        <Label htmlFor={reasonId} className="text-xs">
          Reason (required)
        </Label>
        <Textarea
          id={reasonId}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
          maxLength={TRIAGE_REASON_MAX}
          aria-describedby={hintId}
          aria-invalid={reason.length > 0 && !reasonOk}
          placeholder={state === "false_positive" ? "Why this isn't a real issue here" : "Why, and who agreed it"}
        />
      </div>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={!reasonOk || saving}>
          {saving ? "Saving…" : "Save"}
        </Button>
        <Button variant="ghost" size="sm" onClick={close} disabled={saving}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function UndoTriageButton({
  scanId,
  token,
  checkId,
  onUndone,
}: {
  scanId: string;
  token: string;
  checkId: string;
  onUndone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function undo() {
    setBusy(true);
    setError(null);
    try {
      await callTriageApi("DELETE", token, { scanId, checkId });
      onUndone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-2 print:hidden">
      <Button variant="secondary" size="sm" onClick={undo} disabled={busy}>
        {busy ? "Undoing…" : "Undo"}
      </Button>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
