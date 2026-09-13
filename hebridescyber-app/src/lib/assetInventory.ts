// Populates asset_inventory (022_asset_inventory.sql) as a best-effort side
// effect of a completed scan — never blocks or fails the scan itself if the
// sync errors, matching the "post-completion, never load-bearing" contract
// scanExecution.ts's Phase 2 notifications already follow.
//
// Deliberately informational-only in this first pass: no new Finding is
// pushed for a newly-discovered hostname (unlike the roadmap sketch in
// docs/24-FEATURE-EXPANSION-SPEC.md), since that would mean querying
// "have we seen this hostname before" ahead of scoreFromFindings() inside
// the scan's success-determining Phase 1 — real complexity for a
// foundation-level feature. This can be added later without changing this
// module's shape; the table already has everything a diff would need.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanResults } from "./scanners";
import { getCmsType } from "./scanners/fingerprint";

type AssetRow = {
  owner: string;
  target_url: string;
  hostname: string;
  kind: "domain" | "subdomain";
  cms_type: string | null;
  cloud_hints: string[];
  last_seen_at: string;
};

// Technology categories fingerprint.ts uses for CDN/hosting providers —
// the closest thing this scanner suite has to a "cloud hint" today.
const CLOUD_HINT_CATEGORIES = new Set(["CDN", "Hosting"]);

export async function syncAssetInventory(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string,
  results: ScanResults,
  extended: Record<string, unknown> | undefined
): Promise<void> {
  try {
    const rootHostname = new URL(targetUrl).hostname;
    const technologies = results.fingerprint.status === "checked" ? results.fingerprint.technologies : [];
    const cmsType = getCmsType(technologies);
    const cloudHints = technologies.filter((t) => CLOUD_HINT_CATEGORIES.has(t.category)).map((t) => t.name);

    const now = new Date().toISOString();
    const rows: AssetRow[] = [
      { owner: ownerId, target_url: targetUrl, hostname: rootHostname, kind: "domain", cms_type: cmsType, cloud_hints: cloudHints, last_seen_at: now },
    ];

    // Subfinder (extended tier) is the richer source when it ran; fall back
    // to recon.ts's lighter crt.sh-only list otherwise — same precedence
    // scanExecution.ts's supersedesReconSubdomains already established for
    // the equivalent Finding-level choice.
    const subExtended = extended?.subdomains as { status?: string; subdomains?: { host: string }[] } | undefined;
    if (subExtended?.status === "completed" && subExtended.subdomains) {
      for (const s of subExtended.subdomains) {
        if (s.host === rootHostname) continue;
        rows.push({ owner: ownerId, target_url: targetUrl, hostname: s.host, kind: "subdomain", cms_type: null, cloud_hints: [], last_seen_at: now });
      }
    } else if (results.recon.status === "checked") {
      for (const s of results.recon.subdomains) {
        if (s.name === rootHostname) continue;
        rows.push({ owner: ownerId, target_url: targetUrl, hostname: s.name, kind: "subdomain", cms_type: null, cloud_hints: [], last_seen_at: now });
      }
    }

    // first_seen_at is deliberately absent from every row above — see this
    // module's header and the migration's own comment for why.
    const { error } = await supabaseAdmin.from("asset_inventory").upsert(rows, { onConflict: "owner,hostname" });
    if (error) throw new Error(error.message);
  } catch (err) {
    console.error(`[assetInventory] sync failed for ${targetUrl}:`, (err as Error).message);
  }
}
