// Pull-request dependency check (E-71): given a lockfile's content on the base
// and head of a pull request, report only the vulnerable packages the PR
// *introduces* — a package@version in head that base didn't have — so the
// check gates what the change adds, not the existing backlog.
//
// Reuses the E-67 parsers (dependencyLockfiles.ts) and OSV.dev querybatch
// (osv.ts), so a package is judged exactly as the repository scan judges it.
//
// Evidence discipline:
// - A lockfile that can't be parsed on head, or on base when it exists, is an
//   error for that file and makes the whole result `complete: false`. It is
//   never read as "nothing introduced".
// - An OSV.dev failure fails the whole check (`status: "error"`), never "clean".
// - More introduced packages than we can query → `complete: false`.
// - A lockfile missing on base (newly added) has every head package introduced;
//   a lockfile deleted on head introduces nothing.
import { LOCKFILES, parseLockfile, packageKey, type LockfilePackage, type OsvEcosystem } from "./scanners/dependencyLockfiles";
import { cveIdsOf, fetchOsvVulnDetails, fixedVersionFromVulns, osvSeverity, queryOsvBatch, type OsvVulnDetail } from "./scanners/osv";

export const MAX_DIFF_FILES = 20;
export const MAX_INTRODUCED_QUERIED = 2000;
/** Total lockfile text accepted per request (the route also caps each file). */
export const MAX_TOTAL_CHARS = 20_000_000;
/**
 * Wall-clock budget for parsing. Parsing is synchronous (the lockfile readers
 * are hand-written and take about a second per 5 MB at worst, measured), so
 * it can't be interrupted; the budget is checked between files, and files
 * left over are reported as not checked.
 */
export const PARSE_BUDGET_MS = 20_000;
const MAX_VULN_DETAILS = 500;

export type DiffSeverity = "critical" | "high" | "medium" | "low";
export const SEVERITY_ORDER: DiffSeverity[] = ["low", "medium", "high", "critical"];

export type DiffFileInput = {
  /** Path or basename of the lockfile ("web/package-lock.json" or "Cargo.lock"). */
  name: string;
  /** Content on the PR's base; null when the file doesn't exist there. */
  base: string | null;
  /** Content on the PR's head; null when the PR deletes it. */
  head: string | null;
  base_companion?: string | null;
  head_companion?: string | null;
};

export type DiffFileResult = {
  file: string;
  ecosystem: OsvEcosystem | null;
  status: "ok" | "error";
  error?: string;
  /** Packages in head that base lacks (by name and version). */
  packages_added: number;
  packages_removed: number;
  /** The lockfile is new in this PR: every package counts as introduced. */
  base_missing?: boolean;
};

export type IntroducedVulnerability = {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
  direct: boolean | null;
  dev: boolean | null;
  introduced_via: string[] | null;
  file: string;
  severity: DiffSeverity;
  fixed_version: string | null;
  advisories: { id: string; cve_ids: string[]; severity: DiffSeverity | null; summary: string | null }[];
};

export type DependencyDiffResult =
  | {
      status: "completed";
      /** False when something couldn't be checked; the caller must not treat the result as clean. */
      complete: boolean;
      notes: string[];
      files: DiffFileResult[];
      packages_added: number;
      vulnerabilities: IntroducedVulnerability[];
      counts: Record<DiffSeverity, number>;
    }
  | { status: "error"; error: string };

const basename = (path: string) => path.replace(/\\/g, "/").split("/").pop() as string;

type Introduced = { pkg: LockfilePackage; file: string };

function safeParse(file: string, content: string, companion: string | null | undefined): { ok: true; packages: LockfilePackage[]; ecosystem: OsvEcosystem } | { ok: false; error: string } {
  try {
    const parsed = parseLockfile(basename(file), content, companion);
    return { ok: true, packages: parsed.packages, ecosystem: parsed.ecosystem };
  } catch (err) {
    return { ok: false, error: `${file}: could not be read (${(err as Error).message})` };
  }
}

/** Pure: which packages each file introduces, plus per-file results. */
export function diffLockfiles(files: DiffFileInput[], budgetMs = PARSE_BUDGET_MS): { introduced: Introduced[]; results: DiffFileResult[] } {
  const introduced: Introduced[] = [];
  const results: DiffFileResult[] = [];
  const seen = new Set<string>();
  const deadline = Date.now() + budgetMs;

  for (const input of files) {
    if (Date.now() > deadline) {
      results.push({ file: input.name, ecosystem: null, status: "error", error: `${input.name}: skipped, the parsing time budget was used up`, packages_added: 0, packages_removed: 0 });
      continue;
    }
    const base = basename(input.name);
    const descriptor = LOCKFILES.find((d) => d.file === base);
    if (!descriptor) {
      results.push({ file: input.name, ecosystem: null, status: "error", error: `${input.name}: not a supported lockfile`, packages_added: 0, packages_removed: 0 });
      continue;
    }

    const head = input.head === null ? null : safeParse(input.name, input.head, input.head_companion);
    const before = input.base === null ? null : safeParse(input.name, input.base, input.base_companion);
    const failure = (head && !head.ok ? head.error : null) ?? (before && !before.ok ? before.error : null);
    if (failure) {
      results.push({ file: input.name, ecosystem: descriptor.ecosystem, status: "error", error: failure, packages_added: 0, packages_removed: 0 });
      continue;
    }

    const headPackages = head && head.ok ? head.packages : [];
    const basePackages = before && before.ok ? before.packages : [];
    const baseKeys = new Set(basePackages.map((p) => `${p.ecosystem}:${packageKey(p.name, p.version)}`));
    const headKeys = new Set(headPackages.map((p) => `${p.ecosystem}:${packageKey(p.name, p.version)}`));

    let added = 0;
    for (const pkg of headPackages) {
      const key = `${pkg.ecosystem}:${packageKey(pkg.name, pkg.version)}`;
      if (baseKeys.has(key)) continue;
      added++;
      // The same package@version from two lockfiles of one ecosystem is one thing to fix.
      if (seen.has(key)) continue;
      seen.add(key);
      introduced.push({ pkg, file: input.name });
    }
    results.push({
      file: input.name,
      ecosystem: descriptor.ecosystem,
      status: "ok",
      packages_added: added,
      packages_removed: [...baseKeys].filter((k) => !headKeys.has(k)).length,
      ...(input.base === null && input.head !== null ? { base_missing: true } : {}),
    });
  }
  return { introduced, results };
}

/** The most severe rating; advisories with no rating at all count as medium, as in the repository scan. */
const maxSeverity = (rated: DiffSeverity[]): DiffSeverity =>
  rated.length === 0 ? "medium" : rated.reduce((a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a));

export async function computeDependencyDiff(files: DiffFileInput[]): Promise<DependencyDiffResult> {
  const { introduced: all, results } = diffLockfiles(files);
  const notes: string[] = [];
  let complete = results.every((r) => r.status === "ok");
  if (!complete) notes.push("One or more lockfiles couldn't be read, so they weren't checked.");

  // Direct dependencies first, so a cap drops transitive ones last.
  const ordered = [...all].sort((a, b) => Number(b.pkg.direct === true) - Number(a.pkg.direct === true));
  const introduced = ordered.slice(0, MAX_INTRODUCED_QUERIED);
  if (ordered.length > introduced.length) {
    complete = false;
    notes.push(`This change adds ${ordered.length} packages; only the first ${MAX_INTRODUCED_QUERIED} (direct dependencies first) were checked.`);
  }

  const counts: Record<DiffSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const packagesAdded = all.length;
  if (introduced.length === 0) return { status: "completed", complete, notes, files: results, packages_added: packagesAdded, vulnerabilities: [], counts };

  const batch = await queryOsvBatch(introduced.map(({ pkg }) => ({ ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version })));
  if (!batch.ok) return { status: "error", error: batch.error };

  const affected = introduced.map((item, i) => ({ ...item, ids: batch.vulnIds[i] })).filter((a) => a.ids.length > 0);
  if (affected.length === 0) return { status: "completed", complete, notes, files: results, packages_added: packagesAdded, vulnerabilities: [], counts };
  const allIds = [...new Set(affected.flatMap((a) => a.ids))].sort();
  const { details, failed } = await fetchOsvVulnDetails(allIds.slice(0, MAX_VULN_DETAILS), { concurrency: 10 });
  if (allIds.length > details.size) {
    notes.push(`Advisory details for ${allIds.length - details.size} advisories couldn't be fetched${failed.length ? ` (${failed.slice(0, 3).join(", ")})` : ""}; those packages are still reported, with fewer details.`);
  }

  const vulnerabilities: IntroducedVulnerability[] = [];
  for (const { pkg, file, ids } of affected) {
    // A withdrawn advisory no longer claims anything.
    const live = ids.filter((id) => !details.get(id)?.withdrawn);
    if (live.length === 0) continue;
    const known = live.map((id) => details.get(id));
    const fixed = known.every((d) => d) ? fixedVersionFromVulns(known as OsvVulnDetail[], pkg.ecosystem, pkg.name, pkg.version) : null;
    const advisories = live.sort().map((id) => {
      const d = details.get(id);
      return { id, cve_ids: cveIdsOf(d ? [d] : [{ id }]), severity: d ? osvSeverity(d) : null, summary: d?.summary ? d.summary.slice(0, 200) : null };
    });
    const rated = advisories.map((a) => a.severity).filter((s): s is DiffSeverity => s !== null);
    vulnerabilities.push({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      version: pkg.version,
      direct: pkg.direct,
      dev: pkg.dev ?? null,
      introduced_via: pkg.introducedVia ?? null,
      file,
      severity: maxSeverity(rated),
      fixed_version: fixed,
      advisories,
    });
  }

  vulnerabilities.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || a.name.localeCompare(b.name));
  for (const v of vulnerabilities) counts[v.severity]++;
  return { status: "completed", complete, notes, files: results, packages_added: packagesAdded, vulnerabilities, counts };
}
