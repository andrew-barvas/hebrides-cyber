// Wayback Machine historical path discovery — passively queries the Internet
// Archive's CDX API for every URL it has ever crawled under this domain, then
// live-probes a bounded, prioritised subset of the genuinely interesting ones.
//
// WHY THIS EXISTS ALONGSIDE exposure.ts
// exposure.ts checks a curated, hand-picked list of commonly-sensitive paths.
// That list can only ever contain what's generic across every site on the
// internet — it has no way to know that *this* target once shipped an
// "/admin-old", a "/debug/session-dump", or a "/api/v1/internal-metrics" that
// nobody on any wordlist would ever guess. The Wayback Machine's CDX index is
// a free, no-auth, passive record of exactly that: every path this domain has
// ever served, as observed by the archive's crawlers. This module mines that
// history for paths worth a live check today.
//
// PASSIVE SOURCE, ACTIVE VERIFICATION. Querying the CDX API touches only
// archive.org — never the target. The target is only ever contacted for the
// bounded, prioritised, capped set of candidate paths this module decides are
// worth a live look, using the exact same baseline/masking machinery
// (httpProbe.ts) every other path-probing check here already relies on. A
// path that was archived once but 404s (or hits the site's catch-all shell)
// today is not a finding — the point is "still-live forgotten endpoint", not
// "used to exist".
//
// Follows the same contract as exposure.ts / directoryListing.ts: never
// throws, `{ status: "error" }` only for a malformed target URL, and any CDX
// failure/timeout/empty-result degrades to a clean `{ status: "checked",
// discovered: [] }` rather than surfacing an error — a dead third-party API
// is not evidence of anything about the target.
import { createHash } from "node:crypto";
import {
  type Baseline,
  normaliseBody,
  fetchBaseline,
  matchesBaselineHeaders,
  isCatchAllBody,
} from "./httpProbe";

export type WaybackDiscoveryResult =
  | {
      status: "checked";
      discovered: WaybackLiveFinding[];
      // Diagnostics, not shown to end users directly — useful for confirming
      // the caps below are behaving sanely on a real domain.
      candidatesConsidered: number;
      candidatesProbed: number;
    }
  | { status: "error"; note: string };

export type WaybackLiveFinding = {
  path: string;
  /** Pre-built so index.ts's summariseResults can use it verbatim — see checkId() below. */
  checkId: string;
  severity: "info" | "low";
  name: string;
  hint: string;
};

// ---- Tunables ---------------------------------------------------------------

// Bounds the CDX request itself. A handful of very popular domains have
// millions of archived captures; asking CDX to sort/collapse/return an
// unbounded set would make this module as slow as the site is popular. This
// is a request-size bound, not the live-probe cap below — most of what comes
// back here is filtered out before anything is ever fetched from the target.
const CDX_ROW_LIMIT = 5000;
const CDX_TIMEOUT_MS = 10_000;

// The live-probe cap. A domain with 50,000 archived URLs must not turn into
// 50,000 live requests — this is the number that actually matters for target
// load and scan duration.
const MAX_CANDIDATES_PROBED = 40;

const PROBE_TIMEOUT_MS = 6000;
// Read bound on candidate bodies, mirroring exposure.ts/directoryListing.ts —
// normaliseBody already caps at 4000 chars, this just avoids buffering a
// multi-megabyte response before we get there.
const MAX_BODY_BYTES = 2_000_000;

/**
 * Extensions that are never worth a live check on their own — a stylesheet or
 * font either loads or it doesn't, and neither outcome says anything about
 * forgotten endpoints or exposed data. Checked against the last path segment
 * so query strings and hash fragments in the archived URL don't defeat it.
 */
const STATIC_ASSET_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "avif", "tiff",
  "css",
  "js", "mjs", "cjs",
  "woff", "woff2", "ttf", "eot", "otf",
]);

/** Belt-and-suspenders on top of the extension check, using CDX's own mimetype field. */
const STATIC_ASSET_MIME_PREFIXES = ["image/", "font/", "text/css"];
const STATIC_ASSET_MIME_EXACT = new Set(["application/javascript", "application/x-javascript", "text/javascript"]);

/**
 * Paths already covered by exposure.ts's PROBE_TARGETS and
 * directoryListing.ts's CANDIDATE_PATHS. Neither list is exported (both files
 * are out of scope to edit for this module), so this is a hand-maintained
 * mirror rather than a shared import — kept here purely to avoid re-probing
 * the exact same curated paths a second time under a different check name.
 * If either module's list changes, update this one too; a stale entry here
 * only costs a redundant probe, never a missed finding.
 */
const ALREADY_CURATED_PATHS = new Set<string>([
  "/.git/head", "/.git/config", "/.svn/entries",
  "/.env", "/.env.local", "/.env.production", "/.env.backup",
  "/config.php", "/configuration.php", "/database.yml", "/config/database.yml",
  "/wp-config.php.bak", "/wp-config.php~", "/settings.py",
  "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/site.zip", "/www.zip",
  "/phpinfo.php", "/info.php", "/server-status", "/server-info", "/_profiler", "/telescope",
  "/.well-known/security.txt", "/.htpasswd", "/.htaccess",
  "/storage/logs/laravel.log", "/var/log/app.log", "/error.log",
  "/phpmyadmin", "/phpmyadmin/", "/pma/", "/adminer.php",
  "/uploads/", "/images/", "/assets/", "/static/", "/media/", "/files/", "/downloads/",
  "/backup/", "/backups/", "/old/", "/tmp/", "/temp/", "/log/", "/logs/", "/data/", "/db/",
  "/includes/", "/wp-content/uploads/",
]);

/** Candidates containing any of these get probed before everything else. */
const PRIORITY_KEYWORDS = [
  "admin", "debug", "api", "backup", "old", "test", "staging", "internal", ".bak", "config",
];

/** Subset of the above strongly implying risk if the path is confirmed live today. */
const RISK_KEYWORDS = ["admin", "backup", ".env", "config"];

// Archived-URL noise: crawler artifacts where a chunk of inline JS or a
// malformed href got misparsed as a path (e.g. "/!==l?v.zoom=1:v.display=").
// These are common in large CDX result sets and are never real endpoints, so
// filtering them out here saves live-probe budget for genuine candidates.
const LOOKS_LIKE_CODE = /[<>{}|`"']|==|&&|\|\||\s/;
const MAX_PATH_LENGTH = 200;

// ---- CDX -------------------------------------------------------------------

type CdxRow = [original: string, statuscode: string, mimetype: string];

function extensionOf(pathname: string): string {
  const lastSegment = pathname.split("/").pop() ?? "";
  const dot = lastSegment.lastIndexOf(".");
  return dot === -1 ? "" : lastSegment.slice(dot + 1).toLowerCase();
}

function isStaticAsset(pathname: string, mimetype: string): boolean {
  if (STATIC_ASSET_EXTENSIONS.has(extensionOf(pathname))) return true;
  const mime = mimetype.toLowerCase();
  if (STATIC_ASSET_MIME_EXACT.has(mime)) return true;
  return STATIC_ASSET_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix));
}

function looksLikeRealPath(pathname: string): boolean {
  if (!pathname || pathname === "/") return false;
  if (pathname.length > MAX_PATH_LENGTH) return false;
  if (LOOKS_LIKE_CODE.test(pathname)) return false;
  return true;
}

/**
 * Queries the CDX API for every archived URL under `domain`, then filters to
 * a deduplicated, sorted (for determinism across runs) list of pathnames
 * worth considering as live-probe candidates. Never throws — any failure
 * (network, timeout, malformed response, empty result) resolves to `[]`, and
 * the caller treats that exactly like "Wayback has nothing on this domain".
 */
async function fetchCdxCandidates(domain: string): Promise<string[]> {
  const url =
    `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*` +
    `&output=json&fl=original,statuscode,mimetype&collapse=urlkey&limit=${CDX_ROW_LIMIT}`;

  let rows: unknown;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(CDX_TIMEOUT_MS) });
    if (!res.ok) return [];
    rows = await res.json();
  } catch {
    return [];
  }

  if (!Array.isArray(rows) || rows.length <= 1) return [];

  // First row is the column header (["original","statuscode","mimetype"]),
  // per the CDX API's own documented `output=json` shape — not a data row.
  const dataRows = rows.slice(1) as CdxRow[];

  const seen = new Set<string>();
  for (const row of dataRows) {
    const original = Array.isArray(row) ? row[0] : undefined;
    const mimetype = Array.isArray(row) && typeof row[2] === "string" ? row[2] : "";
    if (typeof original !== "string") continue;

    let pathname: string;
    try {
      pathname = new URL(original).pathname;
    } catch {
      continue;
    }

    if (!looksLikeRealPath(pathname)) continue;
    if (isStaticAsset(pathname, mimetype)) continue;

    const normalised = pathname.toLowerCase();
    if (ALREADY_CURATED_PATHS.has(normalised) || ALREADY_CURATED_PATHS.has(normalised.replace(/\/$/, ""))) continue;

    seen.add(pathname);
  }

  return [...seen].sort((a, b) => a.localeCompare(b));
}

/**
 * Sorted input in, priority-first / cap-applied output out. Sorting the full
 * candidate list before partitioning (rather than after) keeps the selection
 * deterministic run to run for a given CDX snapshot — the same reasoning
 * subdomains.ts uses for its host cap: an unstable selection would make
 * candidates flap between the report's "new" and "fixed" states for no real
 * reason.
 */
function prioritiseAndCap(candidates: string[]): string[] {
  const priority: string[] = [];
  const rest: string[] = [];
  for (const path of candidates) {
    const lower = path.toLowerCase();
    if (PRIORITY_KEYWORDS.some((kw) => lower.includes(kw))) priority.push(path);
    else rest.push(path);
  }
  return [...priority, ...rest].slice(0, MAX_CANDIDATES_PROBED);
}

// ---- Live probing ------------------------------------------------------------

/**
 * checkId is hashed rather than built directly from the path (contrast
 * exposure.ts, which uses its static paths verbatim) because these paths are
 * arbitrary strings pulled from archive history — they can contain characters
 * that would break the "<module>.<check>:<key>" convention findingsDiff.ts
 * parses on, or just be inconveniently long. Hashing keeps the id stable
 * across runs for the same path (the whole point — same path, same id, every
 * time) without either constraint.
 */
export function waybackCheckId(path: string): string {
  const hash = createHash("sha256").update(path).digest("hex").slice(0, 16);
  return `wayback-discovery.live-path:${hash}`;
}

function buildFinding(path: string): WaybackLiveFinding {
  const risky = RISK_KEYWORDS.some((kw) => path.toLowerCase().includes(kw));
  return {
    path,
    checkId: waybackCheckId(path),
    severity: risky ? "low" : "info",
    name: "Historically archived path is still live",
    hint:
      `${path} was found in the Wayback Machine's archive of this domain and ` +
      `responds live today with content distinct from the site's own catch-all/` +
      `404 response. Old admin panels, debug endpoints, and deprecated API ` +
      `routes are routinely forgotten rather than decommissioned — confirm ` +
      `this path is still meant to be publicly reachable.` +
      (risky
        ? " Its name suggests it may expose sensitive functionality or data, which is why this is scored above informational."
        : ""),
  };
}

/**
 * One candidate's live check, reusing the exact baseline/masking machinery
 * exposure.ts and directoryListing.ts both already rely on (see httpProbe.ts's
 * header comment for why: a server that 200s a catch-all shell for every
 * unknown path would otherwise turn every discovered path into a phantom
 * finding). Unlike exposure.ts, there is no per-path content assertion to
 * check against — we don't know what a given historical path is supposed to
 * contain — so passing the catch-all check is the entire evidence bar here:
 * live, and demonstrably not the same document the site serves for a
 * URL we know does not exist.
 */
async function probeCandidate(origin: string, path: string, baseline: Baseline): Promise<WaybackLiveFinding | null> {
  const url = origin + path;
  try {
    const res = await fetch(url, {
      redirect: "manual", // a redirect to the homepage is not "still live"
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (res.status !== 200) return null;
    if (matchesBaselineHeaders(baseline, res)) return null;

    const reader = res.body;
    let text: string;
    if (reader) {
      // Bound how much we read before deciding — a huge legitimate response
      // (e.g. a large JSON export) still only needs its first couple thousand
      // characters to prove it isn't the catch-all shell.
      const buf = await res.arrayBuffer().catch(() => null);
      if (!buf) return null;
      text = Buffer.from(buf.slice(0, MAX_BODY_BYTES)).toString("utf-8");
    } else {
      text = await res.text().catch(() => "");
    }

    const masked = normaliseBody(text, path);
    if (isCatchAllBody(baseline, masked)) return null;

    return buildFinding(path);
  } catch {
    return null; // Network errors are not findings.
  }
}

// ---- Main --------------------------------------------------------------------

/**
 * Discovers historically-archived paths for the target's own hostname via the
 * Wayback Machine's CDX API, then live-probes a bounded, priority-ordered
 * subset. Never throws: a malformed target URL is the only `"error"` case,
 * everything else (no CDX data, every candidate 404s today, network failure)
 * resolves to `{ status: "checked", discovered: [] }`.
 */
export async function checkWaybackDiscovery(targetUrl: string): Promise<WaybackDiscoveryResult> {
  let origin: string;
  let domain: string;
  try {
    const u = new URL(targetUrl);
    origin = u.origin;
    domain = u.hostname;
  } catch {
    return { status: "error", note: "Invalid URL" };
  }

  const candidates = await fetchCdxCandidates(domain);
  const prioritised = prioritiseAndCap(candidates);

  if (prioritised.length === 0) {
    return { status: "checked", discovered: [], candidatesConsidered: candidates.length, candidatesProbed: 0 };
  }

  const baseline = await fetchBaseline(origin);
  const results = await Promise.allSettled(prioritised.map((path) => probeCandidate(origin, path, baseline)));

  const discovered = results
    .filter((r): r is PromiseFulfilledResult<WaybackLiveFinding> => r.status === "fulfilled" && r.value !== null)
    .map((r) => r.value);

  return {
    status: "checked",
    discovered,
    candidatesConsidered: candidates.length,
    candidatesProbed: prioritised.length,
  };
}
