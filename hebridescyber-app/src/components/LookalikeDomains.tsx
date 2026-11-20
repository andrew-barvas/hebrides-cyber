"use client";

// Lookalike domains on the Assets page: every registered lookalike the weekly
// sweep has found for the owner's domains (lookalikeDomainMonitor.ts,
// migration 053; owner-readable under RLS), each with what to do about it
// (LookalikeResponseKit). The alert email links here.
import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { lookalikeTechniqueLabel } from "@/lib/lookalikeResponse";
import { LookalikeResponseKit } from "./LookalikeResponseKit";

type Row = { candidate_domain: string; target_domain: string; technique: string; first_seen_at: string; notified_at: string | null };

const LIMIT = 200;

function day(iso: string | null): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

export default function LookalikeDomains() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { data, error: err } = await supabase
        .from("lookalike_domains")
        .select("candidate_domain, target_domain, technique, first_seen_at, notified_at")
        .order("first_seen_at", { ascending: false })
        .limit(LIMIT);
      if (cancelled) return;
      if (err) setError(true);
      else setRows((data ?? []) as Row[]);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <p className="text-sm text-cybermuted">Lookalike domains couldn&apos;t be loaded just now.</p>;
  if (rows === null) return <p className="text-sm text-cybermuted">Loading…</p>;
  if (rows.length === 0) {
    return (
      <p className="text-sm text-cybermuted">
        None found. Every week or so we check public certificate records for registered domains one character away from yours, and tell you about each one we find.
      </p>
    );
  }

  return (
    <ul className="space-y-2">
      {rows.map((r) => {
        const how = lookalikeTechniqueLabel(r.technique);
        const spotted = r.notified_at ?? r.first_seen_at;
        return (
          <li key={r.candidate_domain} className="rounded-lg border border-cyberborder bg-cyberpanel">
            <details>
              <summary className="cursor-pointer list-none px-4 py-3">
                <span className="font-mono text-cybertext break-all">{r.candidate_domain}</span>{" "}
                <span className="text-sm text-cybermuted">
                  looks like {r.target_domain}, {how}
                  {day(spotted) ? `, spotted ${day(spotted)}` : ""}
                </span>
                <span className="ml-2 text-xs text-neon">What to do</span>
              </summary>
              <div className="border-t border-cyberborder px-4 py-3">
                <LookalikeResponseKit domain={r.candidate_domain} targetDomain={r.target_domain} how={how} spottedAt={spotted} />
              </div>
            </details>
          </li>
        );
      })}
    </ul>
  );
}
