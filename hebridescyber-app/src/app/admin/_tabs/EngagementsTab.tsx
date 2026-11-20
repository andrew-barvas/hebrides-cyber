"use client";

// Admin: run an Exploit engagement (P-07) end to end without hand-written API
// calls. List every engagement, create one for a customer found by email, then
// set its scope, contacts, testing windows, signed contract and rules of
// engagement and expiry, move it on one state at a time (showing why a move
// was refused), and stop it. Every rule stays in /api/engagements*; this tab
// only sends what the analyst typed and shows what came back.
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input, Label } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { AdminEngagementSummary, ContactKind, EngagementView, ScopeChanges, WindowProblem } from "@/lib/engagements";
import { NEXT_STATE, SCOPE_REFUSAL_TEXT, SHA256, WINDOW_PROBLEM_TEXT, describeRefusal, editedDates, fromLocalInput, parseHosts, toLocalInput } from "@/lib/engagementAdmin";
import { CONTACT_LABEL, STATE_LABEL, canStop, formatWhen } from "@/lib/engagementStatus";
import { cn } from "@/lib/utils";
import { ApiError, apiFetch } from "../_shared";

type Row = AdminEngagementSummary & { owner_email: string | null };
type Customer = { id: string; email: string | null };
type ListAnswer = { customer: Customer | null; engagements: Row[]; truncated?: boolean };
type Notice = { variant: "success" | "danger" | "info" | "warning"; text: string } | null;

const PROFILES: Array<[string, string]> = [
  ["exposure", "Exposure (default)"],
  ["safe", "Passive only"],
  ["offensive", "Active testing"],
];
const CONTACT_KINDS: ContactKind[] = ["emergency", "technical", "authoriser"];
const SELECT = "h-10 rounded-md border border-cyberborder bg-cyberbg px-2 text-sm text-cybertext";

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export default function EngagementsTab({ token }: { token: string }) {
  const [lookup, setLookup] = useState("");
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [notice, setNotice] = useState<Notice>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  const [truncated, setTruncated] = useState(false);
  // Only the newest list request may set the list and the customer: an older answer
  // arriving late would otherwise book the next engagement under the wrong account.
  const latest = useRef(0);

  const fetchList = useCallback(
    (forCustomer: string) => apiFetch<ListAnswer>(`/api/admin/engagements${forCustomer ? `?customer=${encodeURIComponent(forCustomer)}` : ""}`, token),
    [token],
  );
  const apply = useCallback((r: ListAnswer) => {
    setRows(r.engagements);
    setCustomer(r.customer);
    setTruncated(r.truncated === true);
  }, []);

  /** Loads a list; false when a newer request has started since. Throws only for the newest request. */
  const loadList = useCallback(
    async (forCustomer: string) => {
      const ticket = ++latest.current;
      let r: ListAnswer;
      try {
        r = await fetchList(forCustomer);
      } catch (e) {
        if (ticket !== latest.current) return false;
        throw e;
      }
      if (ticket !== latest.current) return false;
      apply(r);
      return true;
    },
    [apply, fetchList],
  );

  useEffect(() => {
    const ticket = ++latest.current;
    fetchList("")
      .then((r) => {
        if (ticket === latest.current) apply(r);
      })
      .catch((e) => {
        if (ticket === latest.current) setNotice({ variant: "danger", text: errorText(e) });
      });
  }, [apply, fetchList]);

  async function find() {
    setNotice(null);
    try {
      await loadList(lookup.trim());
    } catch (e) {
      // Don't leave the last search's rows under a message saying there is no such account.
      setCustomer(null);
      setRows([]);
      setTruncated(false);
      setNotice({ variant: "danger", text: errorText(e) });
    }
  }

  async function showAll() {
    setLookup("");
    setNotice(null);
    await loadList("").catch((e) => setNotice({ variant: "danger", text: errorText(e) }));
  }

  const refresh = useCallback(() => {
    loadList(customer?.id ?? "").catch(() => undefined);
  }, [customer?.id, loadList]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Engagements</CardTitle>
            <CardDescription>Booked by us, never self-serve. Find the customer by the email they signed up with to see their engagements or book a new one.</CardDescription>
          </div>
        </CardHeader>
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-full max-w-sm space-y-1">
            <Label htmlFor="eng-customer">Customer email or user id</Label>
            <Input id="eng-customer" value={lookup} onChange={(e) => setLookup(e.target.value)} onKeyDown={(e) => e.key === "Enter" && lookup.trim() && find()} placeholder="name@company.co.uk" />
          </div>
          <Button variant="secondary" onClick={find} disabled={!lookup.trim()}>
            Find customer
          </Button>
          {customer && (
            <Button variant="ghost" onClick={showAll}>
              Show every engagement
            </Button>
          )}
        </div>
        {customer && (
          <CreateForm
            token={token}
            customer={customer}
            onCreated={(id) => {
              setNotice({ variant: "success", text: "Engagement booked. Add its scope, contacts and signed documents below." });
              setOpenId(id);
              refresh();
            }}
            onError={(text) => setNotice({ variant: "danger", text })}
          />
        )}
      </Card>

      {notice && <Alert variant={notice.variant}>{notice.text}</Alert>}

      {rows.length === 0 ? (
        <EmptyState as="h3" title={customer ? `No engagements for ${customer.email ?? customer.id} yet` : "No engagements yet"} description="Find a customer above to book the first one." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-cybermuted">
              <tr>
                <th className="py-1 pr-3">Reference</th>
                <th className="pr-3">Customer</th>
                <th className="pr-3">State</th>
                <th className="pr-3">Window</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={cn("border-t border-cyberborder", openId === r.id && "bg-cybertext/5")}>
                  <td className="py-1 pr-3 font-mono text-xs">{r.reference}</td>
                  <td className="pr-3 text-xs" title={r.owner}>
                    {r.customer_name ? `${r.customer_name} · ` : ""}
                    <span className="font-mono">{r.owner_email ?? r.owner}</span>
                  </td>
                  <td className="pr-3">{STATE_LABEL[r.state]?.title ?? r.state}</td>
                  <td className="pr-3 text-xs text-cybermuted">
                    {formatWhen(r.window_start)} to {formatWhen(r.window_end)}
                  </td>
                  <td>
                    <Button variant="ghost" size="sm" onClick={() => setOpenId(r.id)} aria-label={`Open ${r.reference}`}>
                      Open
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {truncated && <p className="mt-2 text-sm text-cybermuted">Showing the newest {rows.length} engagements. Older ones aren&apos;t listed: find the customer to see all of theirs.</p>}
        </div>
      )}

      {openId && <EngagementDetail key={openId} token={token} id={openId} onChanged={refresh} />}
    </div>
  );
}

function CreateForm({ token, customer, onCreated, onError }: { token: string; customer: Customer; onCreated: (id: string) => void; onError: (text: string) => void }) {
  const [reference, setReference] = useState("");
  const [customerName, setCustomerName] = useState("");
  const [profile, setProfile] = useState("exposure");
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    try {
      const r = await apiFetch<{ engagement: { id: string } }>("/api/engagements", token, {
        method: "POST",
        body: JSON.stringify({ owner: customer.id, reference: reference.trim(), scanProfile: profile, ...(customerName.trim() ? { customerName: customerName.trim() } : {}) }),
      });
      setReference("");
      setCustomerName("");
      onCreated(r.engagement.id);
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 space-y-3 border-t border-cyberborder pt-4">
      <p className="text-sm">
        Book a new engagement for <span className="font-mono">{customer.email ?? customer.id}</span>
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label htmlFor="eng-reference">Reference</Label>
          <Input id="eng-reference" value={reference} onChange={(e) => setReference(e.target.value)} placeholder="ENG-2026-001" className="w-48" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="eng-customer-name">Organisation name (optional)</Label>
          <Input id="eng-customer-name" value={customerName} onChange={(e) => setCustomerName(e.target.value)} className="w-64" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="eng-profile">Testing profile</Label>
          <select id="eng-profile" value={profile} onChange={(e) => setProfile(e.target.value)} className={cn(SELECT, "block")}>
            {PROFILES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <Button onClick={create} disabled={busy || !reference.trim()}>
          Book engagement
        </Button>
      </div>
    </div>
  );
}

type ContactDraft = { kind: ContactKind; name: string; role: string; email: string; phone: string };
type WindowDraft = { startsAt: string; endsAt: string };

function EngagementDetail({ token, id, onChanged }: { token: string; id: string; onChanged: () => void }) {
  const [view, setView] = useState<EngagementView | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);

  const fetchView = useCallback(() => apiFetch<EngagementView>(`/api/engagements/${id}`, token), [id, token]);
  const load = useCallback(async () => setView(await fetchView()), [fetchView]);

  useEffect(() => {
    fetchView()
      .then(setView)
      .catch((e) => setNotice({ variant: "danger", text: errorText(e) }));
  }, [fetchView]);

  // Sections with edits not yet saved, so a refusal never contradicts what the form shows.
  const [dirty, setDirty] = useState<Record<string, boolean>>({});
  const markDirty = useCallback((section: string, isDirty: boolean) => setDirty((d) => (!!d[section] === isDirty ? d : { ...d, [section]: isDirty })), []);
  const unsaved = Object.keys(dirty).filter((s) => dirty[s]);

  /**
   * Sends one change, then reloads the record so the page shows what was stored, not
   * what was typed. The change and the reload are reported apart: a change that went
   * through is never shown as failed because the reload after it didn't.
   */
  async function send(path: string, init: RequestInit, done: string | ((r: unknown) => string), describe?: (e: ApiError) => string) {
    setBusy(true);
    setNotice(null);
    let r: unknown;
    try {
      r = await apiFetch<unknown>(path, token, init);
    } catch (e) {
      setNotice({ variant: "danger", text: e instanceof ApiError && describe ? describe(e) : errorText(e) });
      setBusy(false);
      return false;
    }
    const text = typeof done === "string" ? done : done(r);
    onChanged();
    try {
      await load();
      setNotice({ variant: "success", text });
    } catch {
      setNotice({ variant: "warning", text: `${text} The page couldn't reload the engagement, so it may be out of date. Open it again to see the latest.` });
    } finally {
      setBusy(false);
    }
    return true;
  }

  if (!view) {
    return notice ? <Alert variant={notice.variant}>{notice.text}</Alert> : null;
  }

  const e = view.engagement;
  const editable = e.state === "booked" || e.state === "scoped";
  const next = NEXT_STATE[e.state];
  const patch = (body: unknown, done: string) => send(`/api/engagements/${id}`, { method: "PATCH", body: JSON.stringify(body) }, done, (err) => describeRefusal(err.body, err.message));

  return (
    <Card className="space-y-6">
      <CardHeader className="mb-0">
        <div>
          <h3 className="text-lg font-semibold">Engagement {e.reference}</h3>
          <p className="text-sm text-cybermuted">
            {STATE_LABEL[e.state].title}. {STATE_LABEL[e.state].detail}
          </p>
          {e.state === "aborted" && (
            <p className="text-sm text-cybermuted">
              Stopped {formatWhen(e.aborted_at)}
              {e.abort_reason ? `: ${e.abort_reason}` : ""}
            </p>
          )}
        </div>
      </CardHeader>

      {notice && <Alert variant={notice.variant}>{notice.text}</Alert>}
      {!editable && e.state !== "aborted" && e.state !== "closed" && <Alert variant="info">Scope, contacts, windows and signed documents are fixed once an engagement is authorised, so what was checked stays on record.</Alert>}

      <StateControls
        state={e.state}
        next={next}
        busy={busy}
        unsaved={unsaved}
        onMove={() => next && patch({ to: next }, `Moved to ${STATE_LABEL[next].title}.`)}
        onStop={(reason) =>
          send(`/api/engagements/${id}/abort`, { method: "POST", body: JSON.stringify(reason ? { reason } : {}) }, (r) => {
            const n = (r as { authorisationsRevoked?: number }).authorisationsRevoked ?? 0;
            return `Engagement stopped. ${n} authorisation${n === 1 ? " was" : "s were"} withdrawn. Anything still running stops within about half a minute.`;
          })
        }
      />

      <ScopeSection view={view} editable={editable} busy={busy} send={send} id={id} onDirty={markDirty} />

      <DetailsSection key={`d-${e.window_start}-${e.window_end}-${e.expires_at}-${e.customer_name}`} view={view} editable={editable} busy={busy} patch={patch} onDirty={markDirty} />

      <SignedSection
        key={`s-${e.contract_signed_at}-${e.contract_signed_by_name}-${e.contract_signed_by_role}-${e.contract_document_ref}-${e.roe_signed_at}-${e.roe_document_ref}-${e.roe_document_sha256}-${e.roe_signed_by_name}-${e.roe_signed_by_role}`}
        view={view}
        editable={editable}
        busy={busy}
        patch={patch}
        onDirty={markDirty}
      />

      <ContactsSection key={`c-${view.contacts.map((c) => c.id).join()}`} view={view} editable={editable} busy={busy} send={send} id={id} onDirty={markDirty} />

      <WindowsSection key={`w-${view.testingWindows.map((w) => w.id).join()}`} view={view} editable={editable} busy={busy} send={send} id={id} onDirty={markDirty} />
    </Card>
  );
}

type Send = (path: string, init: RequestInit, done: string | ((r: unknown) => string), describe?: (e: ApiError) => string) => Promise<boolean>;
type Patch = (body: unknown, done: string) => Promise<boolean>;
type OnDirty = (section: string, isDirty: boolean) => void;

/** Tells the detail view whether this section has unsaved edits, and clears that when the section goes away. */
function useReportDirty(section: string, isDirty: boolean, onDirty: OnDirty) {
  useEffect(() => {
    onDirty(section, isDirty);
    return () => onDirty(section, false);
  }, [section, isDirty, onDirty]);
}

function Section({ title, unsaved = false, children }: { title: string; unsaved?: boolean; children: ReactNode }) {
  return (
    <section className="space-y-3 border-t border-cyberborder pt-4">
      <div className="flex items-baseline gap-3">
        <CardTitle as="h3">{title}</CardTitle>
        {unsaved && <span className="text-xs text-warning">Unsaved changes</span>}
      </div>
      {children}
    </section>
  );
}

function StateControls({
  state,
  next,
  busy,
  unsaved,
  onMove,
  onStop,
}: {
  state: EngagementView["engagement"]["state"];
  next: EngagementView["engagement"]["state"] | undefined;
  busy: boolean;
  unsaved: string[];
  onMove: () => void;
  onStop: (reason: string) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  return (
    <Section title="State">
      {next && unsaved.length > 0 && (
        <Alert variant="warning">
          Unsaved changes in {unsaved.join(", ")}. Moving on checks only what is saved, so save them first.
        </Alert>
      )}
      <div className="flex flex-wrap items-center gap-3">
        {next && (
          <Button onClick={onMove} disabled={busy}>
            Move to {STATE_LABEL[next].title}
          </Button>
        )}
        {canStop(state) && !confirming && (
          <Button variant="danger" onClick={() => setConfirming(true)} disabled={busy}>
            Stop engagement
          </Button>
        )}
      </div>
      {confirming && (
        <div className="space-y-3 rounded-lg border border-danger/30 bg-danger/10 p-4">
          <p className="text-sm">Stopping withdraws every authorisation linked to this engagement and halts anything running. It can&apos;t be undone.</p>
          <div className="max-w-md space-y-1">
            <Label htmlFor="eng-stop-reason">Reason (optional)</Label>
            <Input id="eng-stop-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          <div className="flex gap-2">
            <Button
              variant="danger"
              disabled={busy}
              onClick={() => {
                setConfirming(false);
                onStop(reason.trim());
              }}
            >
              Yes, stop this engagement
            </Button>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </Section>
  );
}

function ScopeSection({ view, editable, busy, send, id, onDirty }: { view: EngagementView; editable: boolean; busy: boolean; send: Send; id: string; onDirty: OnDirty }) {
  const [hosts, setHosts] = useState("");
  const [included, setIncluded] = useState(true);
  const isDirty = editable && parseHosts(hosts).length > 0;
  useReportDirty("Scope", isDirty, onDirty);

  const scopeDone = (r: unknown) => {
    const c = r as ScopeChanges;
    const parts = [];
    if (c.added.length) parts.push(`Added ${c.added.map((a) => a.host).join(", ")}.`);
    if (c.removed.length) parts.push(`Removed ${c.removed.join(", ")}.`);
    for (const f of c.refused) parts.push(`Refused ${f.host}: ${Object.hasOwn(SCOPE_REFUSAL_TEXT, f.reason) ? SCOPE_REFUSAL_TEXT[f.reason] : f.reason}.`);
    return parts.join(" ") || "No change.";
  };

  async function add() {
    const list = parseHosts(hosts);
    const ok = await send(`/api/engagements/${id}/scope`, { method: "POST", body: JSON.stringify({ add: list.map((host) => ({ host, included })) }) }, scopeDone);
    if (ok) setHosts("");
  }

  return (
    <Section title="Scope" unsaved={isDirty}>
      {view.scope.length === 0 ? (
        <p className="text-sm text-cybermuted">No hosts yet.</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {view.scope.map((h) => (
            <li key={h.host} className="flex flex-wrap items-center gap-3">
              <span className="font-mono">{h.host}</span>
              <span className={h.included ? "text-neon" : "text-cybermuted"}>{h.included ? "In scope" : "Excluded"}</span>
              {h.included && <span className="text-xs text-cybermuted">{h.authorization ? `Customer authorised ${formatWhen(h.authorization.authorized_at)}` : "Not yet authorised by the customer"}</span>}
              {editable && (
                <Button variant="ghost" size="sm" disabled={busy} onClick={() => send(`/api/engagements/${id}/scope`, { method: "POST", body: JSON.stringify({ remove: [h.host] }) }, scopeDone)} aria-label={`Remove ${h.host}`}>
                  Remove
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {editable && (
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-full max-w-md space-y-1">
            <Label htmlFor="eng-hosts">Hosts to add (one per line)</Label>
            <Textarea id="eng-hosts" value={hosts} onChange={(e) => setHosts(e.target.value)} rows={2} placeholder="shop.example.com" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-host-included">As</Label>
            <select id="eng-host-included" value={included ? "in" : "out"} onChange={(e) => setIncluded(e.target.value === "in")} className={cn(SELECT, "block")}>
              <option value="in">In scope</option>
              <option value="out">Excluded</option>
            </select>
          </div>
          <Button variant="secondary" onClick={add} disabled={busy || parseHosts(hosts).length === 0}>
            Add hosts
          </Button>
        </div>
      )}
    </Section>
  );
}

function DateField({ id, label, value, onChange, disabled }: { id: string; label: string; value: string; onChange: (v: string) => void; disabled: boolean }) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="datetime-local" value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} className="w-56" />
    </div>
  );
}

const DATE_LABEL = { windowStart: "Window opens", windowEnd: "Window closes", expiresAt: "Expires" } as const;

function DetailsSection({ view, editable, busy, patch, onDirty }: { view: EngagementView; editable: boolean; busy: boolean; patch: Patch; onDirty: OnDirty }) {
  const e = view.engagement;
  // What the inputs held when the form opened: only dates edited since are sent, so
  // a stored timestamp is never re-sent in another format or rounded to the minute.
  const [initial] = useState(() => ({ windowStart: toLocalInput(e.window_start), windowEnd: toLocalInput(e.window_end), expiresAt: toLocalInput(e.expires_at) }));
  const [dates, setDates] = useState(initial);
  const [name, setName] = useState(e.customer_name ?? "");

  const { changes, cleared } = editedDates(initial, dates);
  const body: Record<string, string> = { ...changes };
  if (name.trim() && name.trim() !== (e.customer_name ?? "")) body.customerName = name.trim();
  const isDirty = editable && (Object.keys(body).length > 0 || cleared.length > 0);
  useReportDirty("Window and expiry", isDirty, onDirty);

  return (
    <Section title="Window and expiry" unsaved={isDirty}>
      <p className="text-sm text-cybermuted">Times are in your own time zone. Nothing may run after the expiry, which can&apos;t be before the window ends.</p>
      <div className="flex flex-wrap items-end gap-3">
        <DateField id="eng-window-start" label={DATE_LABEL.windowStart} value={dates.windowStart} onChange={(v) => setDates({ ...dates, windowStart: v })} disabled={!editable} />
        <DateField id="eng-window-end" label={DATE_LABEL.windowEnd} value={dates.windowEnd} onChange={(v) => setDates({ ...dates, windowEnd: v })} disabled={!editable} />
        <DateField id="eng-expires" label={DATE_LABEL.expiresAt} value={dates.expiresAt} onChange={(v) => setDates({ ...dates, expiresAt: v })} disabled={!editable} />
        <div className="space-y-1">
          <Label htmlFor="eng-name">Organisation name</Label>
          <Input id="eng-name" value={name} onChange={(ev) => setName(ev.target.value)} disabled={!editable} className="w-56" />
        </div>
        {editable && (
          <Button variant="secondary" onClick={() => patch(body, "Window and expiry saved.")} disabled={busy || Object.keys(body).length === 0}>
            Save window and expiry
          </Button>
        )}
      </div>
      {cleared.length > 0 && (
        <p className="text-sm text-warning">
          {cleared.map((k) => DATE_LABEL[k]).join(", ")}: once set, a date can be changed but not removed.{" "}
          <Button variant="ghost" size="sm" onClick={() => setDates({ ...dates, ...Object.fromEntries(cleared.map((k) => [k, initial[k]])) })}>
            Put it back
          </Button>
        </p>
      )}
    </Section>
  );
}

function SignedSection({ view, editable, busy, patch, onDirty }: { view: EngagementView; editable: boolean; busy: boolean; patch: Patch; onDirty: OnDirty }) {
  const e = view.engagement;
  const [initialContract] = useState(() => ({ documentRef: e.contract_document_ref ?? "", signedAt: toLocalInput(e.contract_signed_at), signedByName: e.contract_signed_by_name ?? "", signedByRole: e.contract_signed_by_role ?? "" }));
  const [initialRoe] = useState(() => ({ documentRef: e.roe_document_ref ?? "", documentSha256: e.roe_document_sha256 ?? "", signedAt: toLocalInput(e.roe_signed_at), signedByName: e.roe_signed_by_name ?? "", signedByRole: e.roe_signed_by_role ?? "" }));
  const [contract, setContract] = useState(initialContract);
  const [roe, setRoe] = useState(initialRoe);
  const isDirty = editable && (JSON.stringify(contract) !== JSON.stringify(initialContract) || JSON.stringify(roe) !== JSON.stringify(initialRoe));
  useReportDirty("Signed contract and rules of engagement", isDirty, onDirty);

  const contractAt = fromLocalInput(contract.signedAt);
  const contractReady = !!contractAt && !!contract.signedByName.trim() && !!contract.signedByRole.trim();
  const roeAt = fromLocalInput(roe.signedAt);
  const sha = roe.documentSha256.trim().toLowerCase();
  const shaOk = !sha || SHA256.test(sha);
  const roeReady = !!roeAt && !!roe.documentRef.trim() && !!roe.signedByName.trim() && !!roe.signedByRole.trim() && shaOk;

  return (
    <Section title="Signed contract and rules of engagement" unsaved={isDirty}>
      <p className="text-sm text-cybermuted">Record where each signed document is filed and who signed it, not the document itself.</p>
      <fieldset className="space-y-2" disabled={!editable}>
        <legend className="text-sm font-medium">Contract</legend>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label htmlFor="eng-contract-ref">Document reference (optional)</Label>
            <Input id="eng-contract-ref" value={contract.documentRef} onChange={(ev) => setContract({ ...contract, documentRef: ev.target.value })} className="w-64" />
          </div>
          <DateField id="eng-contract-at" label="Contract signed" value={contract.signedAt} onChange={(v) => setContract({ ...contract, signedAt: v })} disabled={!editable} />
          <div className="space-y-1">
            <Label htmlFor="eng-contract-name">Contract signed by</Label>
            <Input id="eng-contract-name" value={contract.signedByName} onChange={(ev) => setContract({ ...contract, signedByName: ev.target.value })} className="w-48" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-contract-role">Contract signer&apos;s role</Label>
            <Input id="eng-contract-role" value={contract.signedByRole} onChange={(ev) => setContract({ ...contract, signedByRole: ev.target.value })} className="w-40" />
          </div>
          {editable && (
            <Button
              variant="secondary"
              disabled={busy || !contractReady}
              onClick={() => patch({ contract: { signedAt: contractAt, signedByName: contract.signedByName.trim(), signedByRole: contract.signedByRole.trim(), ...(contract.documentRef.trim() ? { documentRef: contract.documentRef.trim() } : {}) } }, "Contract recorded.")}
            >
              Save contract
            </Button>
          )}
        </div>
      </fieldset>
      <fieldset className="space-y-2" disabled={!editable}>
        <legend className="text-sm font-medium">Rules of engagement</legend>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label htmlFor="eng-roe-ref">Document reference and version</Label>
            <Input id="eng-roe-ref" value={roe.documentRef} onChange={(ev) => setRoe({ ...roe, documentRef: ev.target.value })} className="w-64" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-roe-sha">SHA-256 of the signed file (optional)</Label>
            <Input id="eng-roe-sha" value={roe.documentSha256} onChange={(ev) => setRoe({ ...roe, documentSha256: ev.target.value })} aria-invalid={!shaOk} className="w-96 font-mono text-xs" />
          </div>
          <DateField id="eng-roe-at" label="Rules signed" value={roe.signedAt} onChange={(v) => setRoe({ ...roe, signedAt: v })} disabled={!editable} />
          <div className="space-y-1">
            <Label htmlFor="eng-roe-name">Rules signed by</Label>
            <Input id="eng-roe-name" value={roe.signedByName} onChange={(ev) => setRoe({ ...roe, signedByName: ev.target.value })} className="w-48" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-roe-role">Rules signer&apos;s role</Label>
            <Input id="eng-roe-role" value={roe.signedByRole} onChange={(ev) => setRoe({ ...roe, signedByRole: ev.target.value })} className="w-40" />
          </div>
          {editable && (
            <Button
              variant="secondary"
              disabled={busy || !roeReady}
              onClick={() => patch({ roe: { documentRef: roe.documentRef.trim(), signedAt: roeAt, signedByName: roe.signedByName.trim(), signedByRole: roe.signedByRole.trim(), ...(sha ? { documentSha256: sha } : {}) } }, "Rules of engagement recorded.")}
            >
              Save rules of engagement
            </Button>
          )}
        </div>
        {!shaOk && <p className="text-sm text-danger">A SHA-256 is 64 hexadecimal characters.</p>}
      </fieldset>
    </Section>
  );
}

function ContactsSection({ view, editable, busy, send, id, onDirty }: { view: EngagementView; editable: boolean; busy: boolean; send: Send; id: string; onDirty: OnDirty }) {
  const [initial] = useState<ContactDraft[]>(() => view.contacts.map((c) => ({ kind: c.kind, name: c.name, role: c.role ?? "", email: c.email ?? "", phone: c.phone ?? "" })));
  const [rows, setRows] = useState(initial);
  const set = (i: number, p: Partial<ContactDraft>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const ready = rows.every((r) => r.name.trim() && (r.email.trim() || r.phone.trim()));
  const isDirty = editable && JSON.stringify(rows) !== JSON.stringify(initial);
  useReportDirty("Contacts", isDirty, onDirty);

  function save() {
    const contacts = rows.map((r) => ({
      kind: r.kind,
      name: r.name.trim(),
      ...(r.role.trim() ? { role: r.role.trim() } : {}),
      ...(r.email.trim() ? { email: r.email.trim() } : {}),
      ...(r.phone.trim() ? { phone: r.phone.trim() } : {}),
    }));
    return send(`/api/engagements/${id}/contacts`, { method: "PUT", body: JSON.stringify({ contacts }) }, "Contacts saved.");
  }

  return (
    <Section title="Contacts" unsaved={isDirty}>
      <p className="text-sm text-cybermuted">Authorising needs at least one emergency stop contact. Each contact needs an email address or a phone number.</p>
      {rows.length === 0 && <p className="text-sm text-cybermuted">No contacts yet.</p>}
      <ul className="space-y-2">
        {rows.map((r, i) => (
          <li key={i} className="flex flex-wrap items-end gap-2">
            <select value={r.kind} onChange={(e) => set(i, { kind: e.target.value as ContactKind })} disabled={!editable} className={SELECT} aria-label={`Contact ${i + 1} kind`}>
              {CONTACT_KINDS.map((k) => (
                <option key={k} value={k}>
                  {CONTACT_LABEL[k]}
                </option>
              ))}
            </select>
            <Input value={r.name} onChange={(e) => set(i, { name: e.target.value })} disabled={!editable} placeholder="Name" aria-label={`Contact ${i + 1} name`} className="w-44" />
            <Input value={r.role} onChange={(e) => set(i, { role: e.target.value })} disabled={!editable} placeholder="Role (optional)" aria-label={`Contact ${i + 1} role`} className="w-36" />
            <Input type="email" value={r.email} onChange={(e) => set(i, { email: e.target.value })} disabled={!editable} placeholder="Email" aria-label={`Contact ${i + 1} email`} className="w-56" />
            <Input type="tel" value={r.phone} onChange={(e) => set(i, { phone: e.target.value })} disabled={!editable} placeholder="Phone" aria-label={`Contact ${i + 1} phone`} className="w-40" />
            {editable && (
              <Button variant="ghost" size="sm" onClick={() => setRows(rows.filter((_, j) => j !== i))} aria-label={`Remove contact ${i + 1}`}>
                Remove
              </Button>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => setRows([...rows, { kind: "emergency", name: "", role: "", email: "", phone: "" }])}>
            Add contact
          </Button>
          <Button variant="secondary" onClick={save} disabled={busy || !ready}>
            Save contacts
          </Button>
        </div>
      )}
    </Section>
  );
}

function WindowsSection({ view, editable, busy, send, id, onDirty }: { view: EngagementView; editable: boolean; busy: boolean; send: Send; id: string; onDirty: OnDirty }) {
  const [initial] = useState<WindowDraft[]>(() => view.testingWindows.map((w) => ({ startsAt: toLocalInput(w.starts_at), endsAt: toLocalInput(w.ends_at) })));
  const [rows, setRows] = useState(initial);
  const set = (i: number, p: Partial<WindowDraft>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const ready = rows.every((r) => fromLocalInput(r.startsAt) && fromLocalInput(r.endsAt));
  const isDirty = editable && JSON.stringify(rows) !== JSON.stringify(initial);
  useReportDirty("Testing windows", isDirty, onDirty);

  function save() {
    const windows = rows.map((r) => ({ startsAt: fromLocalInput(r.startsAt), endsAt: fromLocalInput(r.endsAt) }));
    return send(`/api/engagements/${id}/windows`, { method: "PUT", body: JSON.stringify({ windows }) }, "Testing windows saved.", (err) => {
      const reason = err.body.reason as WindowProblem | undefined;
      const index = typeof err.body.index === "number" ? ` (window ${err.body.index + 1})` : "";
      return reason && Object.hasOwn(WINDOW_PROBLEM_TEXT, reason) ? `${WINDOW_PROBLEM_TEXT[reason]}${index}` : err.message;
    });
  }

  return (
    <Section title="Testing windows" unsaved={isDirty}>
      <p className="text-sm text-cybermuted">Optional times inside the overall window, say 09:00 to 17:00 on each agreed day. With none, the overall window is the only limit.</p>
      {rows.length === 0 && <p className="text-sm text-cybermuted">No testing windows.</p>}
      <ul className="space-y-2">
        {rows.map((r, i) => (
          <li key={i} className="flex flex-wrap items-end gap-2">
            <Input type="datetime-local" value={r.startsAt} onChange={(e) => set(i, { startsAt: e.target.value })} disabled={!editable} aria-label={`Testing window ${i + 1} starts`} className="w-56" />
            <span className="pb-2 text-sm text-cybermuted">to</span>
            <Input type="datetime-local" value={r.endsAt} onChange={(e) => set(i, { endsAt: e.target.value })} disabled={!editable} aria-label={`Testing window ${i + 1} ends`} className="w-56" />
            {editable && (
              <Button variant="ghost" size="sm" onClick={() => setRows(rows.filter((_, j) => j !== i))} aria-label={`Remove testing window ${i + 1}`}>
                Remove
              </Button>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => setRows([...rows, { startsAt: "", endsAt: "" }])}>
            Add testing window
          </Button>
          <Button variant="secondary" onClick={save} disabled={busy || !ready}>
            Save testing windows
          </Button>
        </div>
      )}
    </Section>
  );
}
