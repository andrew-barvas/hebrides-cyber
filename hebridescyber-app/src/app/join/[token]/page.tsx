"use client";

// /join/<token> — accept a team invitation (migration 074). Signed out: go
// through sign-up (or sign-in) and come back here. Signed in: accept once and
// say what happened; the API checks the address, expiry and plan.
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { getSession } from "@/lib/auth";

type State = { kind: "working" } | { kind: "joined"; teamName: string; role: string } | { kind: "error"; message: string };

export default function JoinTeamPage() {
  const params = useParams<{ token: string }>();
  const router = useRouter();
  const [state, setState] = useState<State>({ kind: "working" });
  const started = useRef(false);

  useEffect(() => {
    if (started.current || !params?.token) return;
    started.current = true;
    const token = params.token;
    (async () => {
      const session = await getSession();
      if (!session) {
        router.replace(`/signup?redirect=${encodeURIComponent(`/join/${token}`)}`);
        return;
      }
      try {
        const res = await fetch("/api/team/invites/accept", {
          method: "POST",
          headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        const body = (await res.json().catch(() => ({}))) as { teamName?: string; role?: string; error?: string };
        setState(res.ok ? { kind: "joined", teamName: body.teamName ?? "the team", role: body.role ?? "member" } : { kind: "error", message: body.error ?? "This invitation couldn't be accepted." });
      } catch {
        setState({ kind: "error", message: "Couldn't reach the service. Please try again." });
      }
    })();
  }, [params, router]);

  return (
    <div className="mx-auto max-w-md px-6 py-24">
      <h1 className="text-2xl font-bold">Team invitation</h1>
      <div role="status" aria-live="polite" className="mt-6">
        {state.kind === "working" && <p className="text-cybermuted">Checking your invitation…</p>}
        {state.kind === "joined" && (
          <>
            <p className="text-cybertext">
              You&apos;ve joined <strong>{state.teamName}</strong> as {state.role}.
            </p>
            <Link href="/dashboard" className="mt-6 inline-block rounded-md bg-neon px-5 py-2 font-semibold text-cyberbg hover:opacity-90">
              Go to the dashboard
            </Link>
          </>
        )}
        {state.kind === "error" && (
          <>
            <p role="alert" className="text-danger">
              {state.message}
            </p>
            <p className="mt-4 text-sm text-cybermuted">
              Just created your account? Open the invitation link again after confirming your email.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
