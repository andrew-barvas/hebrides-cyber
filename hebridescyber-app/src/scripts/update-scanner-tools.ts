// Checks every pinned scanner tool against its upstream releases and, with
// --write, moves the pins (src/lib/scannerToolUpdates.ts has the rules).
//
//   npm run tools:check                       # report only
//   npm run tools:update -- --tool nuclei     # rewrite nuclei's pins in .github/workflows
//   npm run tools:check -- --json out.json    # machine-readable, for scanner-tool-updates.yml
//
// For a checksum pin the new release asset is downloaded and hashed here, and
// cross-checked against the digest GitHub publishes for the asset when it has
// one; a mismatch is an error, never a bump. GITHUB_TOKEN (read-only is
// enough) raises the API rate limit.
//
// Exit code: 0 when every tool was checked, 2 when any lookup failed (the
// report is still written, so the tools that did check can still be bumped).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  NOT_AUTOMATED,
  SCANNER_TOOLS,
  applyUpdate,
  checkLicence,
  compareVersions,
  pickUpdate,
  pinnedValue,
  prBody,
  releaseAssetUrl,
  readPins,
  type PinUpdate,
  type Release,
  type ScannerTool,
} from "../lib/scannerToolUpdates";

const WORKFLOWS = resolve(__dirname, "../../../.github/workflows");

type Report = {
  id: string;
  status: "update" | "current" | "held" | "error";
  from?: string;
  to?: string;
  reason?: string;
  sha256?: string;
  branch?: string;
  title?: string;
  body?: string;
};

const gh = (path: string) =>
  fetch(`https://api.github.com/${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "hebrides-cyber-tool-updates",
      ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
    signal: AbortSignal.timeout(30_000),
  });

async function json<T>(res: Promise<Response>, what: string): Promise<T> {
  const r = await res;
  if (!r.ok) throw new Error(`${what}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

type GhRelease = { tag_name: string; published_at: string; prerelease: boolean; draft: boolean; assets: { name: string; digest?: string | null }[] };
type PypiFile = { filename: string; url: string; upload_time_iso_8601: string; yanked: boolean; digests: { sha256: string } };

async function githubReleases(repo: string): Promise<GhRelease[]> {
  return json<GhRelease[]>(gh(`repos/${repo}/releases?per_page=40`), `${repo} releases`);
}

async function pypiReleases(pkg: string): Promise<{ releases: Release[]; files: Record<string, PypiFile[]> }> {
  const data = await json<{ releases: Record<string, PypiFile[]> }>(
    fetch(`https://pypi.org/pypi/${pkg}/json`, { signal: AbortSignal.timeout(30_000) }),
    `${pkg} on PyPI`,
  );
  const releases: Release[] = [];
  for (const [version, files] of Object.entries(data.releases)) {
    const live = files.filter((f) => !f.yanked);
    if (live.length === 0) continue;
    const first = live.map((f) => f.upload_time_iso_8601).sort()[0];
    releases.push({ tag: version, publishedAt: first });
  }
  return { releases, files: data.releases };
}

async function upstreamLicence(repo: string): Promise<string | null> {
  try {
    const data = await json<{ license?: { spdx_id?: string } }>(gh(`repos/${repo}/license`), `${repo} licence`);
    return data.license?.spdx_id ?? null;
  } catch {
    return null;
  }
}

async function sha256Of(url: string): Promise<string> {
  const r = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300_000) });
  if (!r.ok) throw new Error(`download ${url}: HTTP ${r.status}`);
  return createHash("sha256").update(Buffer.from(await r.arrayBuffer())).digest("hex");
}

function workflowFiles(): { path: string; text: string }[] {
  return readdirSync(WORKFLOWS)
    .filter((f) => /\.ya?ml$/.test(f))
    .map((f) => ({ path: join(WORKFLOWS, f), text: readFileSync(join(WORKFLOWS, f), "utf8") }));
}

async function checkTool(tool: ScannerTool, files: { path: string; text: string }[], now: Date): Promise<{ report: Report; update?: PinUpdate }> {
  const pins = [...new Set(files.flatMap((f) => readPins(tool, f.text)))];
  if (pins.length === 0) return { report: { id: tool.id, status: "error", reason: "no pin found in .github/workflows" } };
  // Disagreeing pins (one workflow bumped by hand) resolve to the lowest, and every copy is rewritten.
  const current = pins.sort(compareVersions)[0];
  const base: Report = { id: tool.id, status: "current", from: current, ...(pins.length > 1 ? { reason: `workflows disagree: ${pins.join(", ")}` } : {}) };

  let releases: Release[];
  let ghReleases: GhRelease[] = [];
  let pypiFiles: Record<string, PypiFile[]> = {};
  if (tool.kind === "pypi" || tool.kind === "pypi-wheel") {
    const p = await pypiReleases(tool.package);
    releases = p.releases;
    pypiFiles = p.files;
  } else {
    ghReleases = await githubReleases(tool.repo);
    releases = ghReleases.map((r) => ({ tag: r.tag_name, publishedAt: r.published_at, prerelease: r.prerelease, draft: r.draft }));
  }

  const next = pickUpdate(releases, current, now);
  if (!next) return { report: base };

  const held = checkLicence(tool, await upstreamLicence(tool.repo));
  const to = pinnedValue(tool, next.tag);
  if (held) return { report: { ...base, status: "held", to, reason: held } };

  const update: PinUpdate = { version: to };
  if (tool.kind === "release-asset") {
    const url = releaseAssetUrl(tool, to);
    update.sha256 = await sha256Of(url);
    const published = ghReleases.find((r) => r.tag_name === next.tag)?.assets.find((a) => a.name === tool.asset(to))?.digest;
    if (published && published !== `sha256:${update.sha256}`) throw new Error(`${url}: downloaded SHA-256 ${update.sha256} does not match GitHub's ${published}`);
  } else if (tool.kind === "pypi-wheel") {
    const wheel = (pypiFiles[to] ?? []).find((f) => f.filename === `${tool.package}-${to}-py3-none-any.whl` && !f.yanked);
    if (!wheel) throw new Error(`${tool.package} ${to}: no py3-none-any wheel on PyPI`);
    const hashed = await sha256Of(wheel.url);
    if (hashed !== wheel.digests.sha256) throw new Error(`${wheel.url}: downloaded SHA-256 does not match PyPI's`);
    update.sha256 = hashed;
    update.wheelUrl = wheel.url;
  }

  return {
    report: {
      ...base,
      status: "update",
      to,
      sha256: update.sha256,
      branch: `tool-update/${tool.id}-${to.replace(/[^A-Za-z0-9._-]/g, "")}`,
      title: `deps(scanner): bump ${tool.id} from ${current} to ${to}`,
      body: prBody(tool, current, to, next, update.sha256),
    },
    update,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const write = args.includes("--write");
  const jsonOut = args.includes("--json") ? args[args.indexOf("--json") + 1] : undefined;
  const only = args.flatMap((a, i) => (args[i - 1] === "--tool" ? a.split(",") : []));
  const unknown = only.filter((id) => !SCANNER_TOOLS.some((t) => t.id === id));
  if (unknown.length) {
    console.error(`Unknown tool(s): ${unknown.join(", ")}. Known: ${SCANNER_TOOLS.map((t) => t.id).join(", ")}`);
    process.exit(1);
  }

  const files = workflowFiles();
  const now = new Date();
  const reports: Report[] = [];
  for (const tool of SCANNER_TOOLS.filter((t) => only.length === 0 || only.includes(t.id))) {
    try {
      const { report, update } = await checkTool(tool, files, now);
      reports.push(report);
      if (write && update) {
        for (const f of files) {
          const next = applyUpdate(tool, f.text, update);
          if (next !== f.text) {
            f.text = next;
            writeFileSync(f.path, next);
          }
        }
      }
    } catch (err) {
      reports.push({ id: tool.id, status: "error", reason: (err as Error).message });
    }
  }

  for (const r of reports) {
    const arrow = r.to && r.to !== r.from ? ` -> ${r.to}` : "";
    console.log(`${r.status.padEnd(7)} ${r.id.padEnd(17)} ${r.from ?? ""}${arrow}${r.reason ? `  (${r.reason})` : ""}`);
  }
  for (const n of NOT_AUTOMATED) console.log(`manual  ${n.tool.padEnd(17)} ${n.reason}`);
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(reports, null, 2));
  process.exit(reports.some((r) => r.status === "error") ? 2 : 0);
}

void main();
