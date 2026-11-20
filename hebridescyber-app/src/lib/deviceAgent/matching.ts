// CVE and end-of-life matching for a device inventory.
//
// Three sources, each used where it has real evidence:
// - OSV.dev for Linux distribution packages. Debian, Ubuntu, AlmaLinux and
//   Rocky Linux publish their advisories there per release, keyed on the
//   package name and the distro's own version ordering, which OSV compares
//   for us. Debian and Ubuntu key on the *source* package, which the agent
//   sends (dpkg's ${source:Package}).
// - The CPE -> CVE index (cveIndex.ts, P1-3) for desktop applications on
//   Windows and macOS, through CPE_PRODUCTS: a short, curated list of
//   programs whose installed version string is the version NVD uses. A
//   program not on the list is not matched (counted in `coverage`), never
//   mapped by guesswork.
// - endoflife.date (endOfLife.ts) for the operating system.
//
// EVIDENCE RULES (CLAUDE.md rule 7): a source that fails makes the match
// "partial" and adds a note; it never reads as "no CVEs".
import type { CveIndex } from "@/lib/cveIndex";
import { verdictFor, evaluateVersion, type EolEntry, type EolVerdict } from "@/lib/scanners/endOfLife";
import { cveIdsOf, osvCvss, osvSeverity, type OsvBatchQuery, type OsvBatchResult, type OsvVulnDetail } from "@/lib/scanners/osv";
import type { DeviceInventory, InventoryOs } from "./inventorySchema";

export type DeviceCve = {
  /** A CVE id where the advisory has one, else the advisory id. */
  id: string;
  advisoryId: string;
  source: "osv" | "nvd";
  software: string;
  version: string;
  cvssScore: number | null;
  severity: string | null;
  /** true: a fixed version exists; false: none named yet; null: can't tell. */
  fixAvailable: boolean | null;
  fixedVersion: string | null;
  publishedAt: string | null;
  summary: string | null;
};

export type OsEol = {
  product: string;
  cycle: string;
  state: EolVerdict["state"];
  eolDate: string | null;
};

export type DeviceMatch = {
  status: "checked" | "partial";
  matchedAt: string;
  cves: DeviceCve[];
  osEol: OsEol | null;
  /** Why the match is partial. */
  notes: string[];
  coverage: { softwareTotal: number; softwareChecked: number };
};

export type MatchDeps = {
  /** Null when the CVE index store couldn't be opened. */
  cveIndex: CveIndex | null;
  queryOsvBatch: (queries: OsvBatchQuery[]) => Promise<OsvBatchResult>;
  fetchOsvVulnDetails: (ids: string[]) => Promise<{ details: Map<string, OsvVulnDetail>; failed: string[] }>;
  fetchEolProduct: (product: string) => Promise<EolEntry[] | null>;
  now: Date;
};

/** Advisory details fetched per device at most; beyond it the match is partial. */
export const MAX_OSV_DETAILS = 1500;

// ---- Targets ---------------------------------------------------------------------

/** The OSV.dev ecosystem for a Linux release, or null when OSV has none we use. */
export function osvEcosystemFor(os: InventoryOs): string | null {
  if (os.family !== "linux") return null;
  const id = os.distro_id.toLowerCase();
  const v = os.distro_version_id;
  const major = /^(\d+)/.exec(v)?.[1];
  if (id === "debian" && major) return `Debian:${major}`;
  if (id === "ubuntu" && /^\d{2}\.\d{2}$/.test(v)) {
    // Even-year .04 releases are LTS; OSV names them "Ubuntu:22.04:LTS".
    const lts = Number(v.slice(0, 2)) % 2 === 0 && v.endsWith(".04");
    return `Ubuntu:${v}${lts ? ":LTS" : ""}`;
  }
  if (id === "almalinux" && major) return `AlmaLinux:${major}`;
  if (id === "rocky" && major) return `Rocky Linux:${major}`;
  return null;
}

/** OSV queries for a Linux inventory, one per (source) package. */
export function osvQueriesFor(inv: DeviceInventory, ecosystem: string): Array<OsvBatchQuery & { label: string }> {
  const byName = new Map<string, OsvBatchQuery & { label: string }>();
  for (const s of inv.software) {
    if (s.source !== "dpkg" && s.source !== "rpm") continue;
    // Debian/Ubuntu advisories name source packages; Alma/Rocky name binaries.
    const useSource = s.source === "dpkg" && s.source_name;
    const name = useSource ? s.source_name : s.name;
    const version = useSource ? s.source_version || s.version : s.version;
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    if (!byName.has(key)) byName.set(key, { ecosystem, name, version, label: name });
  }
  return [...byName.values()];
}

type CpeProduct = { name: RegExp; vendor: string; product: string; sources?: Array<"registry" | "app" | "pkgutil"> };

// Programs whose reported version is NVD's version for the CPE. Checked by
// hand against NVD's CPE dictionary; add only with the same check. First
// match wins, so specific names come before general ones.
export const CPE_PRODUCTS: CpeProduct[] = [
  { name: /^Google Chrome$/i, vendor: "google", product: "chrome" },
  { name: /^Mozilla Firefox ESR\b/i, vendor: "mozilla", product: "firefox_esr" },
  { name: /^Mozilla Firefox\b|^Firefox$/i, vendor: "mozilla", product: "firefox" },
  { name: /^Mozilla Thunderbird\b|^Thunderbird$/i, vendor: "mozilla", product: "thunderbird" },
  { name: /^Microsoft Edge$/i, vendor: "microsoft", product: "edge_chromium" },
  { name: /^Microsoft Visual Studio Code\b|^Visual Studio Code$/i, vendor: "microsoft", product: "visual_studio_code" },
  { name: /^7-Zip\b/i, vendor: "7-zip", product: "7-zip" },
  { name: /^VLC media player$|^VLC$/i, vendor: "videolan", product: "vlc_media_player" },
  { name: /^PuTTY\b/i, vendor: "putty", product: "putty" },
  { name: /^WinSCP\b/i, vendor: "winscp", product: "winscp" },
  { name: /^FileZilla\b/i, vendor: "filezilla-project", product: "filezilla_client" },
  { name: /^Wireshark\b/i, vendor: "wireshark", product: "wireshark" },
  { name: /^LibreOffice\b/i, vendor: "libreoffice", product: "libreoffice" },
  { name: /^KeePass Password Safe\b|^KeePass$/i, vendor: "keepass", product: "keepass" },
  { name: /^TeamViewer\b/i, vendor: "teamviewer", product: "teamviewer" },
  { name: /^AnyDesk$/i, vendor: "anydesk", product: "anydesk" },
  { name: /^Git$|^Git version /i, vendor: "git-scm", product: "git", sources: ["registry"] },
  { name: /^Node\.js$/i, vendor: "nodejs", product: "node.js", sources: ["registry"] },
  { name: /^Slack$/i, vendor: "slack", product: "slack" },
  { name: /^Safari$/i, vendor: "apple", product: "safari", sources: ["app"] },
];

export function cpeProductFor(name: string, source: string): { vendor: string; product: string } | null {
  for (const p of CPE_PRODUCTS) {
    if (p.sources && !p.sources.includes(source as "registry")) continue;
    if (p.name.test(name.trim())) return { vendor: p.vendor, product: p.product };
  }
  return null;
}

// ---- OS end of life --------------------------------------------------------------

const LINUX_EOL_PRODUCTS: Record<string, string> = {
  ubuntu: "ubuntu",
  debian: "debian",
  rhel: "rhel",
  rocky: "rocky-linux",
  almalinux: "almalinux",
  fedora: "fedora",
  centos: "centos",
  linuxmint: "linuxmint",
  "opensuse-leap": "opensuse",
  sles: "sles",
};

/** The endoflife.date product for this OS, or null. */
export function osEolProduct(os: InventoryOs): string | null {
  if (os.family === "macos") return "macos";
  if (os.family === "windows") return /server/i.test(os.name) ? "windows-server" : "windows";
  return LINUX_EOL_PRODUCTS[os.distro_id.toLowerCase()] ?? null;
}

/**
 * The endoflife.date cycle an OS is on. Windows clients are
 * "<major>-<release>-<w|e>" (Home/Pro vs Enterprise/Education servicing);
 * servers are the year ("2022", "2012-r2"). Null when it can't be placed.
 */
export function placeOsCycle(os: InventoryOs, entries: EolEntry[], now: Date): EolVerdict | null {
  if (os.family === "windows") {
    const has = (cycle: string) => entries.find((e) => String(e.cycle).toLowerCase() === cycle);
    const server = /Server (\d{4})( R2)?/i.exec(os.name);
    if (server) {
      const hit = has(`${server[1]}${server[2] ? "-r2" : ""}`);
      return hit ? verdictFor(hit, now) : null;
    }
    if (/LTSC|LTSB/i.test(os.name)) return null; // long-term channel: its own cycles
    const build = Number(os.build);
    const major = /Windows 11/i.test(os.name) ? "11" : /Windows 10/i.test(os.name) ? "10" : build >= 22000 ? "11" : build > 0 ? "10" : null;
    const release = os.release.trim().toLowerCase();
    if (!major || !/^\d{2}h\d$/.test(release)) return null;
    const edition = /Enterprise|Education|IoT/i.test(os.name) ? "e" : "w";
    const hit = has(`${major}-${release}-${edition}`) ?? has(`${major}-${release}`);
    return hit ? verdictFor(hit, now) : null;
  }
  const version = os.family === "linux" ? os.distro_version_id || os.version : os.version;
  return version ? evaluateVersion(entries, version, now) : null;
}

// ---- NVD helpers -----------------------------------------------------------------

/** "< 1.2.3" in a criterion's range means 1.2.3 is the first fixed version. */
export function fixedVersionFromRange(range: string): string | null {
  const m = /(?:^|,\s*)<\s+([^,\s]+)/.exec(range);
  return m ? m[1] : null;
}

function severityFromScore(score: number | null): string | null {
  if (score === null) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return score > 0 ? "low" : null;
}

// ---- OSV helpers -----------------------------------------------------------------

/** The advisory's rating: osv.ts's reading, else a distro priority (Ubuntu's). */
export function osvRating(detail: OsvVulnDetail): string | null {
  const rated = osvSeverity(detail);
  if (rated) return rated;
  for (const s of detail.severity ?? []) {
    const score = String(s.score ?? "").toLowerCase();
    if (s.type === "Ubuntu" && ["critical", "high", "medium", "low"].includes(score)) return score;
  }
  return null;
}

/** Whether the advisory names a fixed version for this package in this ecosystem. */
export function osvFixFor(detail: OsvVulnDetail, ecosystem: string, name: string): { fixAvailable: boolean | null; fixedVersion: string | null } {
  const affected = (detail.affected ?? []).filter(
    (a) => a.package?.name === name && typeof a.package?.ecosystem === "string" && a.package.ecosystem.split(":").slice(0, 2).join(":") === ecosystem.split(":").slice(0, 2).join(":")
  );
  if (affected.length === 0) return { fixAvailable: null, fixedVersion: null };
  const fixes = affected.flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed))).filter((f): f is string => typeof f === "string" && f.length > 0);
  return fixes.length > 0 ? { fixAvailable: true, fixedVersion: fixes[fixes.length - 1] } : { fixAvailable: false, fixedVersion: null };
}

/** OSV's `published` time (osv.ts's type doesn't carry it). */
function publishedOf(detail: OsvVulnDetail | undefined): string | null {
  const published = (detail as { published?: unknown } | undefined)?.published;
  return typeof published === "string" ? published : null;
}

// ---- Matching --------------------------------------------------------------------

async function matchOsv(inv: DeviceInventory, ecosystem: string, deps: MatchDeps, notes: string[]): Promise<{ cves: DeviceCve[]; checked: number }> {
  const queries = osvQueriesFor(inv, ecosystem);
  if (queries.length === 0) return { cves: [], checked: 0 };
  const batch = await deps.queryOsvBatch(queries.map(({ ecosystem: e, name, version }) => ({ ecosystem: e, name, version })));
  if (!batch.ok) {
    notes.push(`OSV.dev lookup failed (${batch.error}), so package vulnerabilities are unknown.`);
    return { cves: [], checked: 0 };
  }
  const allIds = [...new Set(batch.vulnIds.flat())];
  const wanted = allIds.slice(0, MAX_OSV_DETAILS);
  if (allIds.length > wanted.length) notes.push(`${allIds.length - wanted.length} advisories weren't read in this run (over ${MAX_OSV_DETAILS}).`);
  const { details, failed } = wanted.length > 0 ? await deps.fetchOsvVulnDetails(wanted) : { details: new Map<string, OsvVulnDetail>(), failed: [] };
  if (failed.length > 0) notes.push(`${failed.length} OSV.dev advisories couldn't be read, so their severity is unknown.`);

  const cves: DeviceCve[] = [];
  const seen = new Set<string>();
  queries.forEach((q, i) => {
    for (const advisoryId of batch.vulnIds[i]) {
      const detail = details.get(advisoryId);
      if (detail?.withdrawn) continue;
      const cveId = detail ? cveIdsOf([detail])[0] : undefined;
      const id = cveId ?? advisoryId;
      const key = `${q.name}:${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fix = detail ? osvFixFor(detail, ecosystem, q.name) : { fixAvailable: null, fixedVersion: null };
      const cvss = detail ? osvCvss(detail) : null;
      cves.push({
        id,
        advisoryId,
        source: "osv",
        software: q.name,
        version: q.version,
        cvssScore: cvss?.score ?? null,
        severity: detail ? osvRating(detail) : null,
        ...fix,
        publishedAt: publishedOf(detail),
        summary: detail?.summary ? detail.summary.slice(0, 300) : null,
      });
    }
  });
  return { cves, checked: queries.length };
}

async function matchCpe(inv: DeviceInventory, deps: MatchDeps, notes: string[]): Promise<{ cves: DeviceCve[]; checked: number }> {
  const targets = new Map<string, { vendor: string; product: string; version: string; label: string }>();
  for (const s of inv.software) {
    if (s.source !== "registry" && s.source !== "app" && s.source !== "pkgutil") continue;
    const cpe = cpeProductFor(s.name, s.source);
    if (!cpe || !s.version) continue;
    targets.set(`${cpe.vendor}:${cpe.product}@${s.version}`, { ...cpe, version: s.version, label: s.name });
  }
  if (targets.size === 0) return { cves: [], checked: 0 };
  if (!deps.cveIndex) {
    notes.push("The CVE index couldn't be opened, so application vulnerabilities are unknown.");
    return { cves: [], checked: 0 };
  }
  const cves: DeviceCve[] = [];
  let checked = 0;
  let indexError: string | null = null;
  for (const t of targets.values()) {
    const res = await deps.cveIndex.lookup({ vendor: t.vendor, product: t.product, version: t.version });
    if (res.status === "error") {
      indexError ??= res.note;
      continue;
    }
    if (res.status !== "checked") continue;
    checked++;
    for (const m of res.matches) {
      // Vulnerable only alongside another product (a particular OS, say):
      // the index can't tell whether that holds here.
      if (m.conditional) continue;
      const fixedVersion = fixedVersionFromRange(m.range);
      cves.push({
        id: m.cveId,
        advisoryId: m.cveId,
        source: "nvd",
        software: t.label,
        version: t.version,
        cvssScore: m.cvssScore,
        severity: severityFromScore(m.cvssScore),
        fixAvailable: fixedVersion ? true : null,
        fixedVersion,
        publishedAt: m.publishedAt,
        summary: m.summary,
      });
    }
  }
  if (indexError) notes.push(`CVE index unavailable (${indexError}), so some application vulnerabilities are unknown.`);
  return { cves, checked };
}

async function matchOsEol(os: InventoryOs, deps: MatchDeps, notes: string[]): Promise<OsEol | null> {
  const product = osEolProduct(os);
  if (!product) return null;
  const entries = await deps.fetchEolProduct(product);
  if (!entries) {
    notes.push("endoflife.date couldn't be reached, so OS support status is unknown.");
    return null;
  }
  const verdict = placeOsCycle(os, entries, deps.now);
  if (!verdict) return null;
  return { product, cycle: verdict.cycle, state: verdict.state, eolDate: verdict.state === "supported" ? null : verdict.eolDate };
}

export async function matchInventory(inv: DeviceInventory, deps: MatchDeps): Promise<DeviceMatch> {
  const notes: string[] = [];
  const ecosystem = osvEcosystemFor(inv.os);
  const [osv, cpe, osEol] = await Promise.all([
    ecosystem ? matchOsv(inv, ecosystem, deps, notes) : Promise.resolve({ cves: [], checked: 0 }),
    matchCpe(inv, deps, notes),
    matchOsEol(inv.os, deps, notes),
  ]);
  const cves = [...osv.cves, ...cpe.cves].sort((a, b) => (b.cvssScore ?? -1) - (a.cvssScore ?? -1) || a.id.localeCompare(b.id));
  return {
    status: notes.length > 0 ? "partial" : "checked",
    matchedAt: deps.now.toISOString(),
    cves,
    osEol,
    notes,
    coverage: { softwareTotal: inv.software.length, softwareChecked: osv.checked + cpe.checked },
  };
}

/** A stored match read back from jsonb: trusted only as far as its shape. */
export function asDeviceMatch(raw: unknown): DeviceMatch | null {
  if (!raw || typeof raw !== "object") return null;
  const m = raw as Partial<DeviceMatch>;
  if ((m.status !== "checked" && m.status !== "partial") || !Array.isArray(m.cves) || !Array.isArray(m.notes)) return null;
  return m as DeviceMatch;
}

/**
 * The previous match, cut to the CVEs whose software and version are still
 * installed in `inv`. The inventory route evaluates a fresh report against
 * this until the matching job re-runs, so an upgrade clears its CVEs at once
 * instead of an hour later; a newly installed program waits for the job.
 */
export function carryMatchForward(match: DeviceMatch | null, inv: DeviceInventory): DeviceMatch | null {
  if (!match) return null;
  const installed = new Set<string>();
  for (const s of inv.software) {
    installed.add(`${s.name}@${s.version}`);
    if (s.source_name) installed.add(`${s.source_name}@${s.source_version || s.version}`);
  }
  return { ...match, cves: match.cves.filter((c) => installed.has(`${c.software}@${c.version}`)) };
}
