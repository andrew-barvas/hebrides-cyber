"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import { uptimeStatusLabel, type UptimeLabel } from "@/lib/uptimeLabels";
import { normaliseMonitorUrl, type UptimeStatus } from "@/lib/uptimeProvider";

type Target = { id: string; target_url: string; created_at: string; scan_profile: string };
type AuthStatus = { auth_type: "cookie" | "basic" };

/**
 * Uptime badges, keyed by normalised URL, from the same GET /api/uptime/status
 * the Integrations card reads (so it is Pro-gated and never refreshes faster
 * than that route allows). Optional decoration: any failure, or no UptimeRobot
 * connection, means no badges rather than a guessed status; the Integrations
 * card is where uptime errors are explained.
 */
async function loadUptimeBadges(): Promise<Record<string, UptimeLabel>> {
  try {
    const session = await getSession();
    if (!session) return {};
    const res = await fetch("/api/uptime/status", { headers: { Authorization: `Bearer ${session.access_token}` } });
    if (!res.ok) return {};
    const body = (await res.json()) as { connected?: boolean; monitors?: Array<{ target_url: string; last_status: UptimeStatus | null; missing?: boolean }> };
    if (!body.connected) return {};
    const badges: Record<string, UptimeLabel> = {};
    for (const m of body.monitors ?? []) {
      const key = normaliseMonitorUrl(m.target_url);
      if (key) badges[key] = uptimeStatusLabel(m.last_status, m.missing);
    }
    return badges;
  } catch {
    return {};
  }
}

export default function MonitoredTargets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [authStatus, setAuthStatus] = useState<Record<string, AuthStatus | null>>({});
  const [uptime, setUptime] = useState<Record<string, UptimeLabel>>({});
  const [newUrl, setNewUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // null while loading — the cap is read from monitored_targets_cap()
  // (sql/migrations/018_monitored_targets_plan_cap.sql) rather than
  // duplicated here, so the displayed number can never drift from what
  // the RLS policy actually enforces.
  const [cap, setCap] = useState<number | null>(null);

  async function load() {
    const {
      data: { user },
    } = await supabase.auth.getUser();

    const { data, error: fetchError } = await supabase
      .from("monitored_targets")
      .select("id, target_url, created_at, scan_profile")
      .order("created_at", { ascending: false });
    if (fetchError) setError(fetchError.message);
    const list = (data ?? []) as Target[];
    setTargets(list);

    if (user) {
      // On error (e.g. migration 018 not yet applied to this database —
      // the function doesn't exist), leave cap as null ("unknown") rather
      // than defaulting to 0, which would wrongly disable the add-site
      // form for every account regardless of their real usage.
      const { data: capValue, error: capError } = await supabase.rpc("monitored_targets_cap", { p_owner: user.id });
      if (!capError && typeof capValue === "number") setCap(capValue);
    }

    // Only non-secret column — see target_auth_credentials' own SELECT
    // policy comment (sql/migrations/014_target_auth_credentials.sql) for
    // why cookie_value/basic_username/basic_password are never requested
    // back once saved.
    if (list.length > 0) {
      const { data: creds } = await supabase
        .from("target_auth_credentials")
        .select("monitored_target_id, auth_type")
        .in("monitored_target_id", list.map((t) => t.id));
      const map: Record<string, AuthStatus | null> = {};
      for (const c of (creds ?? []) as Array<{ monitored_target_id: string; auth_type: "cookie" | "basic" }>) {
        map[c.monitored_target_id] = { auth_type: c.auth_type };
      }
      setAuthStatus(map);
    }
    setLoading(false);
  }

  useEffect(() => {
    load();
    loadUptimeBadges().then(setUptime);
  }, []);

  async function addTarget(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return;

    const { error: insertError } = await supabase.from("monitored_targets").insert({ owner: user.id, target_url: newUrl });
    if (insertError) {
      // A cap rejection surfaces as a bare RLS policy-violation message
      // (Postgres code 42501) — translate it rather than showing raw SQL
      // wording to a customer. Any other insert error (bad URL, duplicate,
      // etc.) is shown as-is.
      setError(
        insertError.code === "42501"
          ? `You've reached your plan's limit of ${cap} monitored site${cap === 1 ? "" : "s"}. Upgrade your plan to add more.`
          : insertError.message
      );
      return;
    }
    setNewUrl("");
    await load();
  }

  const atCap = cap !== null && targets.length >= cap;

  async function removeTarget(id: string) {
    await supabase.from("monitored_targets").delete().eq("id", id);
    await load();
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-0.5 font-mono text-xs text-cybermuted uppercase tracking-wide">// monitored sites</h2>
      <p className="mb-4 text-xs text-cybertext/50">
        Scanned automatically on your plan&apos;s schedule (weekly on Basic, daily on Pro/Agency)
        {cap !== null && (
          <>
            {" "}
            — {targets.length} of {cap} site{cap === 1 ? "" : "s"} used.
          </>
        )}
      </p>

      <form onSubmit={addTarget} className="mb-4 flex flex-col gap-2 sm:flex-row">
        <input
          type="url"
          required
          disabled={atCap}
          placeholder={atCap ? "Upgrade your plan to add more sites" : "https://client-site.com"}
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={atCap}
          className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 shadow-glowsm transition-opacity disabled:opacity-50"
        >
          Add site
        </button>
      </form>

      {error && <p className="mb-2 text-sm text-red-400">{error}</p>}

      {loading ? (
        <p className="text-sm text-cybermuted">Loading…</p>
      ) : targets.length === 0 ? (
        <p className="text-sm text-cybermuted">No monitored sites yet — add one above.</p>
      ) : (
        <ul className="divide-y divide-cyberborder text-sm">
          {targets.map((t) => {
            const badge = uptime[normaliseMonitorUrl(t.target_url) ?? ""];
            return (
              <li key={t.id} className="py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-neon/80">{t.target_url}</span>
                    {badge && (
                      <span
                        className={`rounded border border-cyberborder px-1.5 py-0.5 text-[11px] font-semibold ${badge.className}`}
                        title="From your UptimeRobot account (Integrations → Uptime monitoring)"
                      >
                        Uptime: {badge.text}
                      </span>
                    )}
                  </span>
                  <button
                    onClick={() => removeTarget(t.id)}
                    className="text-xs text-cybermuted hover:text-red-400 transition-colors"
                  >
                    Remove
                  </button>
                </div>
                <AuthenticatedScanConfig
                  monitoredTargetId={t.id}
                  status={authStatus[t.id] ?? null}
                  onChange={load}
                />
                <ScanProfileConfig
                  monitoredTargetId={t.id}
                  currentProfile={t.scan_profile ?? "full"}
                  onChange={load}
                />
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/**
 * Per-target authenticated-scan credential — Sprint 3's "authenticated
 * scanning, first slice" (src/lib/scanners/authenticatedCheck.ts). Collapsed
 * by default so it doesn't crowd the common case (most targets never need
 * this) — only expanded state shows the form.
 */
function AuthenticatedScanConfig({
  monitoredTargetId,
  status,
  onChange,
}: {
  monitoredTargetId: string;
  status: AuthStatus | null;
  onChange: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  // "login" is a form-toggle value only — recording a login always saves a
  // "cookie" credential (see record-login.ts), it isn't a fourth stored type.
  const [authType, setAuthType] = useState<"cookie" | "basic" | "login">("cookie");
  const [cookieValue, setCookieValue] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function withToken(): Promise<string | null> {
    const session = await getSession();
    return session?.access_token ?? null;
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const token = await withToken();
    if (!token) {
      setError("Not signed in.");
      return;
    }
    setBusy(true);
    try {
      const url = authType === "login" ? "/api/account/record-login" : "/api/account/target-auth";
      const body =
        authType === "login"
          ? { monitoredTargetId, loginUrl: loginUrl.trim(), username: username.trim(), password, acknowledged }
          : authType === "cookie"
            ? { monitoredTargetId, authType, cookieValue: cookieValue.trim() }
            : { monitoredTargetId, authType, username: username.trim(), password };
      const res = await fetch(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const responseBody = await res.json();
      if (!res.ok) throw new Error(responseBody.error ?? "Could not save credential");
      setCookieValue("");
      setPassword("");
      setLoginUrl("");
      setAcknowledged(false);
      setOpen(false);
      await onChange();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setError(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/target-auth", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ monitoredTargetId }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not remove credential");
      await onChange();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (status) {
    return (
      <div className="mt-1.5 flex items-center gap-2 text-[11px] text-cybermuted">
        <span>
          Authenticated scan connected ({status.auth_type === "cookie" ? "session cookie" : "Basic Auth"})
        </span>
        <button onClick={remove} disabled={busy} className="text-cybermuted hover:text-red-400 disabled:opacity-40 transition-colors">
          Disconnect
        </button>
      </div>
    );
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="mt-1.5 text-[11px] text-cybermuted hover:text-neon transition-colors">
        + Add authenticated scan credential
      </button>
    );
  }

  return (
    <form onSubmit={save} className="mt-2 space-y-2 rounded-md border border-cyberborder bg-cyberbg/50 p-3">
      <p className="text-[11px] text-cybertext/50">
        Re-runs security header/cookie checks against this page using a session cookie or Basic Auth — not a full
        crawl behind login. Stored credentials never appear in this UI again once saved.
      </p>
      <div className="flex gap-2">
        {(["cookie", "basic", "login"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setAuthType(t)}
            className={`rounded-full px-2.5 py-0.5 text-[11px] font-mono border transition-colors ${
              authType === t ? "bg-neon text-cyberbg border-neon" : "border-cyberborder text-cybertext/60 hover:border-neon hover:text-neon"
            }`}
          >
            {t === "cookie" ? "Session cookie" : t === "basic" ? "Basic Auth" : "Recorded login"}
          </button>
        ))}
      </div>
      {authType === "cookie" ? (
        <input
          type="text"
          required
          placeholder="e.g. session=abc123; other=xyz"
          value={cookieValue}
          onChange={(e) => setCookieValue(e.target.value)}
          className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
      ) : authType === "basic" ? (
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            required
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
          />
          <input
            type="password"
            required
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
          />
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-[11px] text-cybertext/50">
            Logs in through the site&apos;s own login form and saves the resulting session — no need to find a
            cookie yourself. Works for a plain username/password form only, not one with an MFA step. Use a
            dedicated test account for this, never your own personal or admin login.
          </p>
          <input
            type="url"
            required
            placeholder="Login page URL, e.g. https://app.example.com/login"
            value={loginUrl}
            onChange={(e) => setLoginUrl(e.target.value)}
            className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
          />
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              type="text"
              required
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
            <input
              type="password"
              required
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
          </div>
          <label className="flex items-start gap-2 text-[11px] text-cybertext/60">
            <input
              type="checkbox"
              required
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              I&apos;m providing credentials for a test account I&apos;m authorised to use for scanning this site —
              not my personal login or anyone else&apos;s.
            </span>
          </label>
        </div>
      )}
      <div className="flex gap-2">
        <button
          disabled={busy}
          className="rounded-md bg-neon px-3 py-1.5 text-xs font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 transition-opacity"
        >
          {busy ? (authType === "login" ? "Logging in…" : "Saving…") : authType === "login" ? "Log in & save" : "Save"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="rounded-md border border-cyberborder px-3 py-1.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
        >
          Cancel
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </form>
  );
}

const PROFILE_OPTIONS: Array<{ value: string; label: string; hint: string }> = [
  { value: "full", label: "Full", hint: "All extended tools" },
  { value: "api", label: "API", hint: "Injection + active scanning + authenticated headers" },
  { value: "cms", label: "CMS", hint: "WPScan/CMSmap + active scan + XSS" },
  { value: "osint", label: "OSINT", hint: "Subfinder, testssl.sh, Trivy, dependency/secret scanning" },
  { value: "safe", label: "Safe", hint: "Base passive checks only, no active tools" },
];

/**
 * Per-target scan profile selector (src/lib/scanProfiles.ts) — which of the
 * extended-tool suite's tools run on this target's scheduled scans.
 * Collapsed by default, same pattern as AuthenticatedScanConfig above.
 */
function ScanProfileConfig({
  monitoredTargetId,
  currentProfile,
  onChange,
}: {
  monitoredTargetId: string;
  currentProfile: string;
  onChange: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  async function setProfile(profile: string) {
    setBusy(true);
    await supabase.from("monitored_targets").update({ scan_profile: profile }).eq("id", monitoredTargetId);
    setBusy(false);
    setOpen(false);
    await onChange();
  }

  const label = PROFILE_OPTIONS.find((p) => p.value === currentProfile)?.label ?? currentProfile;

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="mt-1.5 flex items-center gap-1.5 text-[11px] text-cybermuted hover:text-neon transition-colors">
        <span className="rounded-full border border-cyberborder px-2 py-0.5 font-mono text-[10px]">{label}</span>
        scan profile
      </button>
    );
  }

  return (
    <div className="mt-2 space-y-2 rounded-md border border-cyberborder bg-cyberbg/50 p-3">
      <p className="text-[11px] text-cybertext/50">
        Choose which extended tools run on this target&apos;s scheduled scans.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {PROFILE_OPTIONS.map((p) => (
          <button
            key={p.value}
            disabled={busy}
            onClick={() => setProfile(p.value)}
            title={p.hint}
            className={`rounded-full px-2.5 py-0.5 text-[11px] font-mono border transition-colors disabled:opacity-50 ${
              currentProfile === p.value
                ? "bg-neon text-cyberbg border-neon"
                : "border-cyberborder text-cybertext/60 hover:border-neon hover:text-neon"
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>
      <button
        type="button"
        onClick={() => setOpen(false)}
        className="rounded-md border border-cyberborder px-3 py-1.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
      >
        Cancel
      </button>
    </div>
  );
}
