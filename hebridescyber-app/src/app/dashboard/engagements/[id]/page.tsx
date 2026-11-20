"use client";

// /dashboard/engagements/<id> — one authorised testing engagement, for the
// customer: what is in scope, when testing may run, who signed what, each
// system's authorisation, and a stop button that is always there until the
// engagement is closed. The stop calls POST /api/engagements/{id}/abort, which
// withdraws every authorisation for the engagement in one transaction; the
// worker gate then refuses any new test step, and the watchdog
// (src/lib/offensiveWatchdog.ts) stops a step already running within one interval.
import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/alert";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { CONTACT_LABEL, STATE_LABEL, authorisationEndsBeforeWindow, authorisationExpiryFor, canAuthorise, canStop, formatWhen, testingAllowedNow } from "@/lib/engagementStatus";
import type { EngagementView } from "@/lib/engagements";

export default function EngagementStatusPage() {
  const { accessToken } = useAppSession();
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<EngagementView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmingStop, setConfirmingStop] = useState(false);
  const [stopReason, setStopReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [authorising, setAuthorising] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const load = useCallback(async () => {
    if (!accessToken || !params?.id) return;
    const r = await fetch(`/api/engagements/${params.id}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (r.ok) setData((await r.json()) as EngagementView);
    else setError(r.status === 404 ? "Engagement not found." : "Couldn't load this engagement. Refresh to try again.");
  }, [accessToken, params]);

  useEffect(() => {
    void load();
  }, [load]);

  async function stop() {
    if (!accessToken || !data) return;
    setBusy(true);
    setError(null);
    const r = await fetch(`/api/engagements/${data.engagement.id}/abort`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(stopReason.trim() ? { reason: stopReason.trim() } : {}),
    });
    setBusy(false);
    if (r.ok) {
      const body = (await r.json()) as { authorisationsRevoked: number };
      setConfirmingStop(false);
      setNotice(`Testing is stopped. ${body.authorisationsRevoked} authorisation${body.authorisationsRevoked === 1 ? " was" : "s were"} withdrawn. Anything still running stops within about half a minute, and nothing new starts.`);
      await load();
    } else {
      setError("The stop didn't go through. Try again, and if it still fails, phone your emergency contact at Hebrides Cyber.");
    }
  }

  async function authorise(host: string, targetUrl: string) {
    if (!accessToken || !data) return;
    setBusy(true);
    setError(null);
    const r = await fetch("/api/account/offensive-authorization", {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ targetUrl, acknowledge: true, engagementId: data.engagement.id, expiresAt: authorisationExpiryFor(data.engagement.expires_at, new Date()) }),
    });
    setBusy(false);
    setAuthorising(null);
    setAcknowledged(false);
    if (r.ok) {
      setNotice(`${host} is authorised for this engagement.`);
      await load();
    } else {
      const body = (await r.json().catch(() => ({}))) as { error?: string };
      setError(body.error ?? "Couldn't record the authorisation. Please try again.");
    }
  }

  if (error && !data) {
    return (
      <p role="alert" className="text-sm text-danger">
        {error}
      </p>
    );
  }
  if (!data) return <p className="text-sm text-cybermuted">Loading…</p>;

  const { engagement, scope, contacts, testingWindows } = data;
  const label = STATE_LABEL[engagement.state];
  const now = testingAllowedNow(engagement, testingWindows, new Date());
  const included = scope.filter((s) => s.included);
  const tooEarlyToAuthorise = canAuthorise(engagement.state) && authorisationEndsBeforeWindow(engagement, new Date());
  const excluded = scope.filter((s) => !s.included);

  return (
    <>
      <PageHeader title={`Engagement ${engagement.reference}`} description={engagement.customer_name ?? undefined} />

      {notice && (
        <Alert variant="success" className="mb-4">
          {notice}
        </Alert>
      )}
      {error && (
        <Alert variant="danger" role="alert" className="mb-4">
          {error}
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Status</CardTitle>
          </CardHeader>
          <p className="text-lg font-semibold">{label.title}</p>
          <CardDescription>{label.detail}</CardDescription>
          <p className={`mt-3 text-sm ${now.allowed ? "font-semibold text-warning" : "text-cybermuted"}`}>{now.allowed ? "Testing may be running now." : `Not testing now: ${now.why}.`}</p>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Stop testing</CardTitle>
          </CardHeader>
          <CardDescription>
            {canStop(engagement.state)
              ? "If anything looks wrong, stop the engagement. Every authorisation for it is withdrawn at once, anything running stops within about half a minute, and nothing new starts. Restarting needs a new authorisation."
              : "This engagement can no longer run any test."}
          </CardDescription>
          {canStop(engagement.state) && (
            <div className="mt-4 space-y-3">
              {!confirmingStop ? (
                <Button variant="danger" size="lg" onClick={() => setConfirmingStop(true)}>
                  Stop testing now
                </Button>
              ) : (
                <>
                  <label className="block text-sm" htmlFor="stop-reason">
                    Reason (optional)
                  </label>
                  <Textarea id="stop-reason" maxLength={500} value={stopReason} onChange={(e) => setStopReason(e.target.value)} placeholder="For example: the site is slow" />
                  <div className="flex flex-wrap gap-2">
                    <Button variant="danger" disabled={busy} onClick={stop}>
                      {busy ? "Stopping…" : "Yes, stop all testing"}
                    </Button>
                    <Button variant="ghost" disabled={busy} onClick={() => setConfirmingStop(false)}>
                      Cancel
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}
        </Card>
      </div>

      <section className="mt-6 space-y-2">
        <h2 className="text-lg font-semibold">When testing may run</h2>
        <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-cybermuted">Window</dt>
          <dd>
            {formatWhen(engagement.window_start)} to {formatWhen(engagement.window_end)}
          </dd>
          <dt className="text-cybermuted">Authorisation ends</dt>
          <dd>{formatWhen(engagement.expires_at)}</dd>
        </dl>
        {testingWindows.length > 0 ? (
          <ul className="list-disc pl-5 text-sm">
            {testingWindows.map((w) => (
              <li key={w.id}>
                {formatWhen(w.starts_at)} to {formatWhen(w.ends_at)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-cybermuted">Testing may run at any time inside the window.</p>
        )}
      </section>

      <section className="mt-6 space-y-2">
        <h2 className="text-lg font-semibold">In scope</h2>
        <p className="text-sm text-cybermuted">Only these systems are tested. Anything not listed is never touched, and the platform enforces that.</p>
        {tooEarlyToAuthorise && (
          <Alert variant="warning">An authorisation lasts at most 30 days, and one signed today would end before the testing window does. Sign within 30 days of the window&apos;s end.</Alert>
        )}
        {included.length === 0 && <p className="text-sm text-cybermuted">No systems are in scope yet.</p>}
        <ul className="divide-y divide-cyberborder">
          {included.map((s) => (
            <li key={s.host} className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm">
              <span className="font-mono">{s.host}</span>
              {s.authorization ? (
                <span className="text-neon">Authorised until {formatWhen(s.authorization.expires_at)}</span>
              ) : canAuthorise(engagement.state) ? (
                s.targetUrls.length === 0 ? (
                  <span className="text-cybermuted">Add {s.host} as a monitored site first, then authorise it here.</span>
                ) : authorising === s.host ? (
                  <span className="flex flex-col items-end gap-2">
                    <label className="flex max-w-md items-start gap-2 text-xs">
                      <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />
                      <span>
                        I own {s.host} or am authorised to commission this test, and I authorise Hebrides Cyber to send real test traffic to it under engagement {engagement.reference}, within the agreed scope and window.
                      </span>
                    </label>
                    <span className="flex gap-2">
                      <Button size="sm" disabled={!acknowledged || busy} onClick={() => authorise(s.host, s.targetUrls[0])}>
                        Authorise
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setAuthorising(null)}>
                        Cancel
                      </Button>
                    </span>
                  </span>
                ) : (
                  <Button size="sm" variant="secondary" onClick={() => setAuthorising(s.host)}>
                    Authorise testing
                  </Button>
                )
              ) : (
                <span className="text-cybermuted">Not authorised</span>
              )}
            </li>
          ))}
        </ul>
        {excluded.length > 0 && (
          <>
            <h3 className="pt-2 font-semibold">Explicitly out of scope</h3>
            <ul className="list-disc pl-5 font-mono text-sm">
              {excluded.map((s) => (
                <li key={s.host}>{s.host}</li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="mt-6 space-y-2">
        <h2 className="text-lg font-semibold">Signed documents</h2>
        <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-cybermuted">Engagement contract</dt>
          <dd>
            {engagement.contract_signed_at
              ? `Signed ${formatWhen(engagement.contract_signed_at)} by ${engagement.contract_signed_by_name ?? "unknown"} (${engagement.contract_signed_by_role ?? "role not recorded"})${engagement.contract_document_ref ? `, ${engagement.contract_document_ref}` : ""}`
              : "Not signed yet"}
          </dd>
          <dt className="text-cybermuted">Rules of engagement</dt>
          <dd>
            {engagement.roe_signed_at
              ? `Signed ${formatWhen(engagement.roe_signed_at)} by ${engagement.roe_signed_by_name ?? "unknown"} (${engagement.roe_signed_by_role ?? "role not recorded"}), ${engagement.roe_document_ref ?? ""}`
              : "Not signed yet"}
          </dd>
        </dl>
      </section>

      <section className="mt-6 space-y-2">
        <h2 className="text-lg font-semibold">Contacts</h2>
        {contacts.length === 0 ? (
          <p className="text-sm text-cybermuted">No contacts recorded yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {contacts.map((c) => (
              <li key={c.id}>
                <span className="text-cybermuted">{CONTACT_LABEL[c.kind] ?? c.kind}:</span> {c.name}
                {c.role ? `, ${c.role}` : ""}
                {c.email ? ` · ${c.email}` : ""}
                {c.phone ? ` · ${c.phone}` : ""}
              </li>
            ))}
          </ul>
        )}
      </section>

      {engagement.state === "aborted" && engagement.aborted_at && (
        <p className="mt-6 text-sm text-cybermuted">
          Stopped {formatWhen(engagement.aborted_at)}
          {engagement.abort_reason ? `: ${engagement.abort_reason}` : "."}
        </p>
      )}
    </>
  );
}
