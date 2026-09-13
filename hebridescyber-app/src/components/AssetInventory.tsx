"use client";

// Renders asset_inventory (022_asset_inventory.sql), populated as a
// best-effort side effect of every completed scan by
// src/lib/assetInventory.ts's syncAssetInventory(). Grouped by target_url
// so each scanned domain shows its own CMS/cloud hints with its discovered
// subdomains nested underneath — same self-contained "fetch via the anon
// client, RLS-scoped" pattern as FleetOverview.tsx.

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

type AssetRow = {
  id: string;
  target_url: string;
  hostname: string;
  kind: "domain" | "subdomain";
  cms_type: string | null;
  cloud_hints: string[];
  last_seen_at: string;
};

type TargetGroup = {
  targetUrl: string;
  domain: AssetRow | null;
  subdomains: AssetRow[];
};

function groupByTarget(rows: AssetRow[]): TargetGroup[] {
  const map = new Map<string, TargetGroup>();
  for (const row of rows) {
    let group = map.get(row.target_url);
    if (!group) {
      group = { targetUrl: row.target_url, domain: null, subdomains: [] };
      map.set(row.target_url, group);
    }
    if (row.kind === "domain") group.domain = row;
    else group.subdomains.push(row);
  }
  return [...map.values()];
}

export default function AssetInventory() {
  const [groups, setGroups] = useState<TargetGroup[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("asset_inventory")
        .select("id, target_url, hostname, kind, cms_type, cloud_hints, last_seen_at")
        .order("target_url", { ascending: true })
        .order("kind", { ascending: true }); // "domain" < "subdomain" — parent row first within each group

      setGroups(groupByTarget((data ?? []) as AssetRow[]));
      setLoading(false);
    })();
  }, []);

  if (loading) {
    return <p className="font-mono text-sm text-cybertext/30">// loading…</p>;
  }

  if (groups.length === 0) {
    return <p className="text-sm text-cybertext/50">No assets discovered yet — run a scan to populate your inventory.</p>;
  }

  return (
    <div className="space-y-4">
      {groups.map((group) => (
        <div key={group.targetUrl} className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-cybertext">{group.domain?.hostname ?? group.targetUrl}</span>
            {group.domain?.cms_type && (
              <span className="rounded-full border border-neon/30 bg-neon/10 px-2 py-0.5 text-xs text-neon">{group.domain.cms_type}</span>
            )}
            {group.domain?.cloud_hints.map((hint) => (
              <span key={hint} className="rounded-full border border-cyberborder bg-cyberbg px-2 py-0.5 text-xs text-cybertext/60">
                {hint}
              </span>
            ))}
            {group.subdomains.length > 0 && (
              <span className="text-xs text-cybertext/40">
                {group.subdomains.length} subdomain{group.subdomains.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
          {group.subdomains.length > 0 && (
            <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 border-t border-cyberborder pt-3">
              {group.subdomains.map((s) => (
                <li key={s.id} className="font-mono text-xs text-cybertext/60">
                  {s.hostname}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}
