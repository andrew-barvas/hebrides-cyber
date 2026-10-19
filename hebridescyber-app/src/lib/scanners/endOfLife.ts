// End-of-life software detection, backed by https://endoflife.date.
//
// Two users:
//   - dockerBaseImage.ts: is the repo's Dockerfile base image past EOL?
//   - checkEndOfLife() below: is a versioned technology the site itself
//     reveals (fingerprint.ts headers/HTML, webapp.ts's CMS and CDN probes)
//     past EOL, or about to be?
//
// End of life is a different question from "has known CVEs" (osv.ts,
// softwareCveDb.ts, wpvdb.ts): it means the maintainer has stopped
// publishing security fixes, so whatever is found from now on stays
// unfixed. Cyber Essentials' "Security update management" control requires
// unsupported software to be removed or upgraded, which is why this maps
// there.
//
// EVIDENCE RULES
//   - A version is matched to a cycle only exactly: "7.4.3" → cycle "7.4",
//     "3.6.1" → cycle "3". A version naming only a major ("Drupal 9") whose
//     cycles are per-minor counts as unsupported only if every minor in that
//     major is past EOL; if any is still supported we can't tell which one
//     the site runs, so nothing is reported.
//   - Upstream EOL is not the whole story for server software installed from
//     a Linux distribution: Ubuntu, Debian and Red Hat backport security fixes
//     into the versions they ship long after upstream stops. When the header
//     that revealed the version also names a distribution, the finding is
//     downgraded and says so rather than claiming the server is unpatched.
//   - A failed endoflife.date lookup makes the whole check an error, never
//     "nothing unsupported" — otherwise a scan during an outage would mark
//     last scan's EOL findings fixed (see findingLifecycle.ts).
//
// Deliberately not covered:
//   - WordPress: endoflife.date marks each release EOL the day the next one
//     ships, while the WordPress security team backports fixes to old
//     branches. That would flag nearly every site. Core CVEs are covered by
//     softwareCveDb.ts instead.
//   - IIS and Ghost: endoflife.date has no product for them.
//   - AngularJS: webapp.ts already reports every 1.x version.
import type { FingerprintResult } from "./fingerprint";
import type { WebAppResult } from "./webapp";
import { collectTechInventory, type TechObservation } from "./techInventory";

const ENDOFLIFE_TIMEOUT_MS = 8_000;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Heads-up window before an EOL date. */
export const APPROACHING_EOL_DAYS = 90;

export type EolEntry = { cycle: string; eol: string | boolean; codename?: string; latest?: string };

// Best-effort, in-process cache, like osv.ts's. Only successes are cached:
// a worker shard runs many scans, and one transient failure must not turn
// every later lookup in the same process into an error.
const eolCache = new Map<string, EolEntry[]>();

export async function fetchEolProduct(product: string): Promise<EolEntry[] | null> {
  const cached = eolCache.get(product);
  if (cached) return cached;

  try {
    const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(product)}.json`, {
      signal: AbortSignal.timeout(ENDOFLIFE_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as unknown;
    if (!Array.isArray(body)) return null;
    const entries = body as EolEntry[];
    eolCache.set(product, entries);
    return entries;
  } catch {
    return null;
  }
}

/** Test hook: forget cached product data. */
export function clearEolCache(): void {
  eolCache.clear();
}

function extractMajorMinor(tag: string): string | null {
  const match = tag.match(/^(\d+\.\d+)/);
  return match ? match[1] : null;
}

function extractMajorOnly(tag: string): string | null {
  const match = tag.match(/^(\d+)/);
  return match ? match[1] : null;
}

/**
 * Matches a Dockerfile tag against a product's endoflife.date cycles. Tries
 * numeric cycles first (covers node/python/go/ruby/php/alpine/ubuntu/
 * postgres/mysql/mongodb/redis/nginx, all of which use "major" or
 * "major.minor" cycle strings), then falls back to a codename match — Debian
 * tags are commonly a codename ("bullseye", "bookworm") rather than a
 * number, and endoflife.date's Debian entries carry that codename.
 */
export function matchEolEntry(entries: EolEntry[], tag: string): EolEntry | null {
  const tagLower = tag.toLowerCase();
  for (const candidate of [extractMajorMinor(tagLower), extractMajorOnly(tagLower)]) {
    if (!candidate) continue;
    const hit = entries.find((e) => String(e.cycle) === candidate);
    if (hit) return hit;
  }
  return entries.find((e) => e.codename && tagLower.includes(String(e.codename).toLowerCase())) ?? null;
}

export function isPastEol(entry: EolEntry, now: Date): boolean {
  if (typeof entry.eol === "boolean") return entry.eol === true;
  const eolDate = new Date(entry.eol);
  if (Number.isNaN(eolDate.getTime())) return false;
  return eolDate.getTime() <= now.getTime();
}

// ---- Web technologies ---------------------------------------------------------

/**
 * platform: server software, often installed from a distribution (backports).
 * application: a CMS the site owner upgrades themselves.
 * library: client-side code served to visitors.
 */
export type EolKind = "platform" | "application" | "library";

type TechProduct = { product: string; label: string; kind: EolKind };

// Keys are fingerprint.ts / webapp.ts technology names. Every product slug
// was checked against https://endoflife.date/api/<slug>.json before being
// added.
export const TECH_EOL_PRODUCTS: Record<string, TechProduct> = {
  PHP: { product: "php", label: "PHP", kind: "platform" },
  Nginx: { product: "nginx", label: "nginx", kind: "platform" },
  Apache: { product: "apache-http-server", label: "Apache HTTP Server", kind: "platform" },
  Drupal: { product: "drupal", label: "Drupal", kind: "application" },
  Joomla: { product: "joomla", label: "Joomla", kind: "application" },
  // Only the platforms that can show a version on a public page. PrestaShop and
  // OpenCart have no endoflife.date product (404), and Moodle and Craft CMS
  // publish no version, so they would never produce a verdict.
  TYPO3: { product: "typo3", label: "TYPO3", kind: "application" },
  Umbraco: { product: "umbraco", label: "Umbraco", kind: "application" },
  Angular: { product: "angular", label: "Angular", kind: "library" },
  jQuery: { product: "jquery", label: "jQuery", kind: "library" },
  Bootstrap: { product: "bootstrap", label: "Bootstrap", kind: "library" },
};

export type EolCandidate = {
  tech: string;
  version: string;
  /** Distribution named alongside the version (e.g. "Ubuntu"), if any. */
  packagedBy?: string | null;
};

export type EolVerdict =
  | { state: "unsupported"; cycle: string; eolDate: string | null; daysOverdue: number | null }
  | { state: "approaching"; cycle: string; eolDate: string; daysLeft: number }
  | { state: "supported"; cycle: string };

function eolDateOf(entry: EolEntry): Date | null {
  if (typeof entry.eol !== "string") return null;
  const d = new Date(entry.eol);
  return Number.isNaN(d.getTime()) ? null : d;
}

function verdictFor(entry: EolEntry, now: Date): EolVerdict {
  const cycle = String(entry.cycle);
  if (entry.eol === true) return { state: "unsupported", cycle, eolDate: null, daysOverdue: null };
  const date = eolDateOf(entry);
  if (!date) return { state: "supported", cycle };
  const diffDays = Math.floor((date.getTime() - now.getTime()) / DAY_MS);
  if (date.getTime() <= now.getTime()) return { state: "unsupported", cycle, eolDate: entry.eol as string, daysOverdue: -diffDays };
  if (diffDays <= APPROACHING_EOL_DAYS) return { state: "approaching", cycle, eolDate: entry.eol as string, daysLeft: diffDays };
  return { state: "supported", cycle };
}

/**
 * Where `version` stands against a product's cycles, or null when it can't be
 * placed with evidence (see "EVIDENCE RULES" above).
 */
export function evaluateVersion(entries: EolEntry[], version: string, now: Date): EolVerdict | null {
  const parts = version.trim().split(".");
  if (!/^\d+$/.test(parts[0] ?? "")) return null;
  const major = parts[0];
  const majorMinor = parts.length >= 2 && /^\d+$/.test(parts[1]) ? `${major}.${parts[1]}` : null;

  const exact = (majorMinor && entries.find((e) => String(e.cycle) === majorMinor)) || entries.find((e) => String(e.cycle) === major);
  if (exact) return verdictFor(exact, now);

  // "Drupal 9" against cycles 9.0 … 9.5: only a verdict every minor agrees on.
  if (parts.length === 1) {
    const branch = entries.filter((e) => String(e.cycle).startsWith(`${major}.`));
    if (branch.length === 0) return null;
    if (!branch.every((e) => isPastEol(e, now))) return null;
    const dates = branch.map(eolDateOf).filter((d): d is Date => d !== null);
    if (dates.length < branch.length) return { state: "unsupported", cycle: `${major}.x`, eolDate: null, daysOverdue: null };
    const last = new Date(Math.max(...dates.map((d) => d.getTime())));
    return {
      state: "unsupported",
      cycle: `${major}.x`,
      eolDate: last.toISOString().slice(0, 10),
      daysOverdue: Math.floor((now.getTime() - last.getTime()) / DAY_MS),
    };
  }
  return null;
}

/**
 * Severity reflects how sure we are that nothing is patching it. Over a year
 * past EOL (or EOL with no date, which only very old cycles have) is treated
 * as long overdue.
 */
export function eolSeverity(kind: EolKind, daysOverdue: number | null, packagedBy?: string | null): "high" | "medium" | "low" {
  const longOverdue = daysOverdue === null || daysOverdue > 365;
  if (kind === "platform") {
    if (packagedBy) return "low"; // the distribution may still be backporting fixes
    return longOverdue ? "high" : "medium";
  }
  if (kind === "application") return longOverdue ? "high" : "medium";
  return longOverdue ? "medium" : "low";
}

export type EolItem = {
  tech: string;
  label: string;
  product: string;
  kind: EolKind;
  version: string;
  packagedBy: string | null;
} & (
  | { state: "unsupported"; cycle: string; eolDate: string | null; daysOverdue: number | null }
  | { state: "approaching"; cycle: string; eolDate: string; daysLeft: number }
);

export type EndOfLifeResult =
  /** `evaluated`: technologies a verdict was reached for, supported or not. */
  | { status: "checked"; items: EolItem[]; evaluated: string[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

/**
 * Versioned technologies worth checking, from the shared inventory
 * (techInventory.ts — which also decides that webapp.ts's more precise
 * versions win over fingerprint.ts's). Client libraries webapp.ts already
 * reported as vulnerable are skipped, so a library gets one finding, not two.
 */
export function collectEolCandidates(fingerprint: FingerprintResult, webapp: WebAppResult | null): EolCandidate[] {
  return collectTechInventory(fingerprint, webapp)
    .filter((o): o is TechObservation & { version: string } => Boolean(o.version) && Boolean(TECH_EOL_PRODUCTS[o.tech]) && !o.reportedVulnerable)
    .map((o) => (o.source === "fingerprint" ? { tech: o.tech, version: o.version, packagedBy: o.packagedBy } : { tech: o.tech, version: o.version }));
}

export async function checkEndOfLife(
  fingerprint: FingerprintResult,
  webapp: WebAppResult | null,
  now: Date = new Date()
): Promise<EndOfLifeResult> {
  const candidates = collectEolCandidates(fingerprint, webapp);
  if (candidates.length === 0) {
    return { status: "not_applicable", note: "No technology with a readable version was detected." };
  }

  const products = [...new Set(candidates.map((c) => TECH_EOL_PRODUCTS[c.tech].product))];
  const data = new Map<string, EolEntry[] | null>(await Promise.all(products.map(async (p) => [p, await fetchEolProduct(p)] as const)));
  const failed = products.filter((p) => !data.get(p));
  if (failed.length > 0) {
    return { status: "error", note: `endoflife.date lookup failed for: ${failed.join(", ")}` };
  }

  const items: EolItem[] = [];
  const evaluated: string[] = [];
  for (const c of candidates) {
    const meta = TECH_EOL_PRODUCTS[c.tech];
    const verdict = evaluateVersion(data.get(meta.product)!, c.version, now);
    if (!verdict) continue;
    evaluated.push(c.tech);
    const base = { tech: c.tech, label: meta.label, product: meta.product, kind: meta.kind, version: c.version, packagedBy: c.packagedBy ?? null };
    if (verdict.state === "unsupported") items.push({ ...base, ...verdict });
    // A distribution's support window isn't upstream's — no countdown for those.
    else if (verdict.state === "approaching" && !c.packagedBy) items.push({ ...base, ...verdict });
  }
  return { status: "checked", items, evaluated };
}
