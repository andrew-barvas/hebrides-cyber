// Public security profiles (migration 073): an opt-in page and badge for one
// verified site. What's public is chosen to help the customer, never an
// attacker: the grade, score, last-checked date and the good practices the
// site passes. Open findings, their count and their severity are never shown,
// and a practice that fails is simply left off the list rather than marked
// as failing.
//
// A profile whose latest completed scan is older than STALE_AFTER_DAYS says
// so, rather than showing an old grade as current.
import { randomBytes } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./scanners";
import { hostOf } from "./findingLifecycle";

export const STALE_AFTER_DAYS = 30;

export type PracticeKey = "https" | "modern-tls" | "email-auth" | "headers";

const PRACTICES: Array<{ key: PracticeKey; label: string; failsOn: string[] }> = [
  { key: "https", label: "Served securely over HTTPS with a valid certificate", failsOn: ["tls.no-https", "tls.cert-expired", "tls.cert-untrusted", "tls.self-signed", "tls.cert-name-mismatch"] },
  { key: "modern-tls", label: "Modern encryption only (no outdated TLS versions)", failsOn: ["tls.weak-protocol"] },
  { key: "email-auth", label: "Email protected against spoofing (SPF and DMARC)", failsOn: ["dns.spf-missing", "dns.dmarc-missing", "dns.dmarc-none"] },
  { key: "headers", label: "Browser security headers in place", failsOn: ["headers.missing-critical", "headers.csp-absent", "tls.hsts-missing"] },
];

export type PublicProfile = {
  host: string;
  score: number | null;
  checkedAt: string | null;
  stale: boolean;
  passes: Array<{ key: PracticeKey; label: string }>;
};

/** A random, unguessable, URL-safe slug (lowercase letters and digits). */
export function newProfileSlug(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  return [...randomBytes(16)].map((b) => alphabet[b % alphabet.length]).join("");
}

export function isProfileSlug(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9]{12,32}$/.test(value);
}

/**
 * Pure: the public view of a site from its latest completed scan. A practice
 * passes only when the scan evaluated the area it belongs to (its result is
 * "checked") and produced none of the findings that fail it.
 */
export function buildPublicProfile(input: {
  host: string;
  scan: { score: number | null; checkedAt: string; findings: Finding[]; evaluated: Partial<Record<"tls" | "dns" | "headers", boolean>> } | null;
  now?: Date;
}): PublicProfile {
  const now = input.now ?? new Date();
  if (!input.scan) return { host: input.host, score: null, checkedAt: null, stale: true, passes: [] };
  const ids = new Set(input.scan.findings.map((f) => (f.checkId ?? "").split(":")[0]));
  const area: Record<PracticeKey, "tls" | "dns" | "headers"> = { https: "tls", "modern-tls": "tls", "email-auth": "dns", headers: "headers" };
  const passes = PRACTICES.filter((p) => input.scan!.evaluated[area[p.key]] === true && !p.failsOn.some((id) => ids.has(id))).map(({ key, label }) => ({ key, label }));
  const ageDays = (now.getTime() - Date.parse(input.scan.checkedAt)) / 86_400_000;
  return { host: input.host, score: input.scan.score, checkedAt: input.scan.checkedAt, stale: !(ageDays <= STALE_AFTER_DAYS), passes };
}

/**
 * Pure: the badge, as an SVG string. `rating` is executiveReport.ts's
 * ratingFor (fixed labels and colours) and the score is a number, so nothing
 * here needs escaping.
 */
export function renderBadgeSvg(profile: Pick<PublicProfile, "score" | "stale">, rating: { label: string; colour: string }): string {
  const current = !profile.stale && profile.score !== null;
  const right = current ? `${rating.label} · ${profile.score}/100` : "not checked recently";
  const colour = current ? rating.colour : "#6b7280";
  const leftW = 118;
  const rightW = Math.max(70, right.length * 7 + 16);
  const w = leftW + rightW;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="Hebrides Cyber security check: ${right}"><title>Hebrides Cyber security check: ${right}</title><rect width="${leftW}" height="20" fill="#0b3d5b"/><rect x="${leftW}" width="${rightW}" height="20" fill="${colour}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="8" y="14">Hebrides Cyber</text><text x="${leftW + 8}" y="14">${right}</text></g></svg>`;
}

// ---- Loaders (service role) --------------------------------------------------

type ProfileRow = { owner: string; target_host: string; slug: string };

export async function loadProfileBySlug(supabaseAdmin: SupabaseClient, slug: string): Promise<ProfileRow | null> {
  if (!isProfileSlug(slug)) return null;
  const { data, error } = await supabaseAdmin.from("security_profiles").select("owner, target_host, slug").eq("slug", slug).maybeSingle();
  if (error || !data) return null;
  return data as ProfileRow;
}

/** The latest completed scan of the profile's host by its owner, or null. */
export async function loadLatestScanForProfile(supabaseAdmin: SupabaseClient, row: ProfileRow): Promise<Parameters<typeof buildPublicProfile>[0]["scan"]> {
  const { data: scans } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, created_at")
    .eq("owner", row.owner)
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(50);
  const scan = (scans ?? []).find((s: { target_url: string }) => hostOf(s.target_url) === row.target_host) as { id: string; created_at: string } | undefined;
  if (!scan) return null;
  const { data: result } = await supabaseAdmin.from("scan_results").select("results, score, created_at").eq("scan_id", scan.id).order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (!result) return null;
  const results = (result.results ?? {}) as { findings?: Finding[]; checked_at?: string; tls?: { status?: string }; dns?: { status?: string }; headers?: { status?: string } };
  return {
    score: typeof result.score === "number" ? result.score : null,
    checkedAt: results.checked_at ?? result.created_at,
    findings: results.findings ?? [],
    evaluated: { tls: results.tls?.status === "checked", dns: results.dns?.status === "checked", headers: results.headers?.status === "checked" },
  };
}
