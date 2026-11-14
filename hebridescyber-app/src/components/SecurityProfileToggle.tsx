"use client";

// Owner-only, on the scan report: publish or remove the public security
// profile for this site (/api/security-profile, src/lib/securityProfile.ts),
// with the link and a copy-ready badge snippet once published.
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

type State = { kind: "loading" } | { kind: "off" } | { kind: "on"; slug: string } | { kind: "error"; message: string };

export default function SecurityProfileToggle({ targetUrl, token }: { targetUrl: string; token: string }) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/security-profile?targetUrl=${encodeURIComponent(targetUrl)}`, { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res): Promise<State> => {
        if (!res.ok) return { kind: "error", message: "Couldn't load the profile setting." };
        const body = (await res.json()) as { slug: string | null };
        return body.slug ? { kind: "on", slug: body.slug } : { kind: "off" };
      })
      .catch((): State => ({ kind: "error", message: "Couldn't load the profile setting." }))
      .then((next) => {
        if (!cancelled) setState(next);
      });
    return () => {
      cancelled = true;
    };
  }, [targetUrl, token]);

  async function change(method: "POST" | "DELETE") {
    setBusy(true);
    try {
      const res = await fetch("/api/security-profile", {
        method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl }),
      });
      const body = (await res.json().catch(() => ({}))) as { slug?: string; error?: string };
      if (!res.ok) setState({ kind: "error", message: body.error ?? "That didn't work. Please try again." });
      else setState(method === "POST" && body.slug ? { kind: "on", slug: body.slug } : { kind: "off" });
    } finally {
      setBusy(false);
    }
  }

  const url = state.kind === "on" ? `${SITE}/profile/${state.slug}` : "";
  const badge = state.kind === "on" ? `<a href="${url}"><img src="${SITE}/api/profile-badge/${state.slug}" alt="Hebrides Cyber security check"></a>` : "";

  return (
    <Card className="print:hidden">
      <CardHeader>
        <div className="min-w-0">
          <CardTitle as="h2">public security profile</CardTitle>
          <CardDescription className="mt-1">
            An optional public page for this site showing its grade, score, last check and the good practices it passes. Open problems are never shown.
          </CardDescription>
        </div>
      </CardHeader>
      {state.kind === "loading" && <p className="text-sm text-cybermuted">Loading…</p>}
      {state.kind === "error" && (
        <p role="alert" className="text-sm text-danger">
          {state.message}
        </p>
      )}
      {state.kind === "off" && (
        <Button onClick={() => change("POST")} disabled={busy}>
          {busy ? "Publishing…" : "Publish profile"}
        </Button>
      )}
      {state.kind === "on" && (
        <div className="space-y-3 text-sm">
          <p>
            Published at{" "}
            <a href={url} className="break-all font-semibold text-neon underline-offset-2 hover:underline">
              {url}
            </a>
          </p>
          <label htmlFor="badge-snippet" className="block text-cybermuted">
            Badge for your website (copy this HTML):
          </label>
          <textarea id="badge-snippet" readOnly value={badge} rows={3} className="w-full rounded-md border border-cyberborder bg-cyberbg p-2 font-mono text-xs text-cybertext" />
          <Button variant="secondary" onClick={() => change("DELETE")} disabled={busy}>
            {busy ? "Removing…" : "Remove profile"}
          </Button>
        </div>
      )}
    </Card>
  );
}
