// Known framework secrets, via badsecrets (Black Lantern Security,
// https://github.com/blacklanternsecurity/badsecrets). It reads what a page
// already hands every visitor — signed cookies, ASP.NET/JSF ViewState, JWTs,
// Telerik and Symfony values — and checks whether the key that signed or
// encrypted them is one of thousands of publicly known defaults (framework
// sample keys, keys copied from tutorials and Stack Overflow). A match means
// anyone can forge sessions or, for ViewState/Shiro/Telerik, often run code.
//
// Licensing: badsecrets is AGPL-3.0 (its LICENSE file; its pyproject.toml says
// GPL-3.0). It runs UNMODIFIED as a separate program, installed into its own
// virtualenv on the scan worker and invoked as a subprocess — never imported,
// linked or redistributed. Owner decision 2026-10-19; attribution in
// docs/THIRD-PARTY-NOTICES.md.
//
// Posture: --passive-only. badsecrets' active modules send crafted values to
// the target to test for keys; passive mode only fetches the URL (the same
// GET a browser makes) and analyses the response offline.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
//   - --json prints nothing BOTH when nothing was found AND when badsecrets
//     couldn't connect (cli.py returns quietly), so we fetch the target
//     ourselves first: unreachable → "error", never an empty "completed";
//   - a non-zero exit or output that isn't JSON → "error";
//   - only `SecretFound` results are findings. `IdentifyOnly` (product
//     recognised, key not in the list) is not evidence of anything;
//   - the matched key and the cookie/token value are NEVER stored or shown:
//     a known key is still this site's live signing key. Findings carry a
//     SHA-256 fingerprint of the key so a rotation is visible as a change.
//
// CLI flags and the JSON shape were taken from the badsecrets 1.2.0 source
// (badsecrets/examples/cli.py, badsecrets/base.py) and are checked against the
// real program by badsecrets.integration.test.ts in tool-integration.yml.
import { createHash } from "node:crypto";
import { execTool } from "../../lib/execTool";
import type { Finding } from "../../lib/scanners";
import { CRAWLER_USER_AGENT } from "../../lib/scanners/crawler";
import { badsecretsRemediation } from "../../lib/scanners/remediationText";

const PROBE_TIMEOUT_MS = 30_000;
const SCAN_TIMEOUT_MS = 90_000;
const REQUEST_TIMEOUT_S = 15;

export type BadsecretsRawResult = {
  type?: string;
  detecting_module?: string;
  location?: string;
  secret?: unknown;
  description?: { product?: string; secret?: string; severity?: string };
};

export type BadsecretsResult =
  | { status: "completed"; findings: Finding[]; identified: string[] }
  | { status: "not_configured" | "error"; findings: []; note: string };

function badsecretsBinary(): string {
  return process.env.BADSECRETS_BIN || "badsecrets";
}

export function buildBadsecretsArgs(targetUrl: string): string[] {
  return ["--json", "--passive-only", "--no-color", "-a", CRAWLER_USER_AGENT, "-t", String(REQUEST_TIMEOUT_S), "-u", targetUrl];
}

/**
 * badsecrets prints one JSON array per phase (only the passive one here), or
 * nothing at all. Throws on anything else.
 */
export function parseBadsecretsOutput(stdout: string): BadsecretsRawResult[] {
  const out: BadsecretsRawResult[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parsed: unknown = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error("badsecrets output is not a JSON array");
    out.push(...(parsed as BadsecretsRawResult[]));
  }
  return out;
}

export function badsecretsSeverity(severity: string | undefined): Finding["severity"] {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "high"; // a confirmed known key is never trivial
  }
}

/** Module names are Python class names ("Flask_SignedCookies"); keep them id-safe. */
function moduleKey(module: string | undefined): string {
  return (module ?? "").replace(/[^A-Za-z0-9_]/g, "") || "unknown";
}

function fingerprint(secret: unknown): string | null {
  if (secret === undefined || secret === null || secret === "") return null;
  const text = typeof secret === "string" ? secret : JSON.stringify(secret);
  return createHash("sha256").update(text).digest("hex").slice(0, 12);
}

const LOCATION_WORDS: Record<string, string> = { cookies: "a cookie", headers: "a response header", body: "the page body" };

/** One finding per detecting module; locations and key fingerprints merged. */
export function buildBadsecretsFindings(results: BadsecretsRawResult[], targetUrl: string): { findings: Finding[]; identified: string[] } {
  const byModule = new Map<string, { raw: BadsecretsRawResult; locations: Set<string>; fingerprints: Set<string> }>();
  const identified = new Set<string>();

  for (const r of results) {
    const mod = moduleKey(r.detecting_module);
    if (r.type !== "SecretFound") {
      if (r.type === "IdentifyOnly" && r.description?.product) identified.add(r.description.product);
      continue;
    }
    const entry = byModule.get(mod) ?? { raw: r, locations: new Set<string>(), fingerprints: new Set<string>() };
    if (r.location) entry.locations.add(r.location);
    const fp = fingerprint(r.secret);
    if (fp) entry.fingerprints.add(fp);
    byModule.set(mod, entry);
  }

  const findings: Finding[] = [...byModule.entries()].map(([module, { raw, locations, fingerprints }]) => {
    const product = raw.description?.product || module;
    const secretLabel = raw.description?.secret || "secret key";
    const where = [...locations].map((l) => LOCATION_WORDS[l] ?? l).join(", ") || "the response";
    const fps = [...fingerprints];
    return {
      checkId: `badsecrets.known-secret:${module}`,
      severity: badsecretsSeverity(raw.description?.severity),
      title: `[badsecrets] ${product} uses a publicly known ${secretLabel}`,
      detail:
        `${targetUrl} returns a ${product} value (in ${where}) that was signed or encrypted with a ${secretLabel} from a public list of known and default keys. ` +
        `Anyone with that list can forge or decrypt these values.` +
        (fps.length ? ` Key fingerprint (SHA-256, first 12 hex): ${fps.join(", ")}. The key itself is not stored.` : ""),
      remediation: badsecretsRemediation(module, product, secretLabel),
      metadata: { module, product, locations: [...locations], keyFingerprints: fps },
    };
  });

  return { findings, identified: [...identified] };
}

type ExecFailure = { code?: string | number; killed?: boolean; message?: string; stderr?: string };

/**
 * Never throws. No binary → not_configured; target unreachable, tool failure
 * or unreadable output → error.
 */
export async function runBadsecrets(targetUrl: string): Promise<BadsecretsResult> {
  try {
    // No --version flag: `-l` lists modules and exits 0.
    await execTool(badsecretsBinary(), ["-l", "--no-color"], { timeout: PROBE_TIMEOUT_MS, maxBuffer: 1024 * 1024 });
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.code === "ENOENT") {
      return { status: "not_configured", findings: [], note: "badsecrets is not installed in this environment — skipping known-secret checks." };
    }
    return { status: "error", findings: [], note: `badsecrets -l failed: ${(failure.message ?? "unknown error").slice(0, 300)}` };
  }

  // badsecrets is silent when it can't connect, so prove the page answers first.
  try {
    const res = await fetch(targetUrl, { headers: { "User-Agent": CRAWLER_USER_AGENT }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_S * 1000) });
    await res.body?.cancel();
  } catch (err) {
    return { status: "error", findings: [], note: `Target unreachable, so badsecrets' silence would mean nothing: ${(err as Error).message}` };
  }

  let stdout: string;
  try {
    ({ stdout } = await execTool(badsecretsBinary(), buildBadsecretsArgs(targetUrl), { timeout: SCAN_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }));
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.killed) return { status: "error", findings: [], note: `badsecrets exceeded ${SCAN_TIMEOUT_MS / 1000}s` };
    const why = (failure.stderr || failure.message || "unknown error").replace(/\s+/g, " ").slice(0, 300);
    return { status: "error", findings: [], note: `badsecrets failed (exit ${String(failure.code ?? "?")}): ${why}` };
  }

  let raw: BadsecretsRawResult[];
  try {
    raw = parseBadsecretsOutput(stdout);
  } catch (err) {
    return { status: "error", findings: [], note: `could not parse badsecrets output: ${(err as Error).message}` };
  }
  const { findings, identified } = buildBadsecretsFindings(raw, targetUrl);
  return { status: "completed", findings, identified };
}
