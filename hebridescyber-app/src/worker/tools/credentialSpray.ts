// Credential spraying via THC-Hydra — the Tier A offensive suite's login
// brute-force. This is the single most sensitive tool in the product: it sends
// real authentication attempts at a login endpoint. It exists so an owner can
// test whether their own login withstands credential attacks (missing lockout /
// rate-limiting), under their own explicit per-scan authorization.
//
// HARD INTERLOCKS (all required, else { status: "not_configured" } and nothing
// runs):
//   - the `hydra` binary;
//   - CREDENTIAL_SPRAY_LOGIN — a SINGLE login the owner has designated as a
//     sacrificial TEST account. Only this one account is ever tried, so real
//     users are never sprayed or locked out;
//   - CREDENTIAL_SPRAY_WORDLIST — a small password list the owner supplies;
//   - CREDENTIAL_SPRAY_FORM — the hydra http-post-form spec for the login
//     (path:body:failure-condition), so the tool never guesses the login shape.
// On top of that it runs under the `offensive` scan profile only, which the
// worker unlocks solely for a Tier A owner with a current offensive
// authorization against an ownership-verified domain.
//
// Lockout-avoidance: one login only, low parallelism (-t 1), and `-f` (stop at
// the first hit). The owner controls the password-list size.
//
// UNVERIFIED end to end: there is no real credential target in CI, so only the
// output parser (against real captured hydra v9.5 output, fixtures/hydra/) and
// the not_configured interlocks are tested. Do not claim it is verified. Enable
// it only after the product/ToS decision to allow real attack traffic.

import { execTool } from "../../lib/execTool";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "../../lib/scanners/index";

const HYDRA_TIMEOUT_MS = 180_000;

export type SprayCredential = { login: string; password: string };

export type CredentialSprayResult =
  | { status: "completed"; found: SprayCredential[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

/**
 * Pure: hydra's `-o` output-file content to the credentials it recovered.
 * Success lines are `[PORT][module] host: H   login: L   password: P`
 * (THC-Hydra v9.5); the `# Hydra …` header and anything else are ignored.
 */
export function parseHydraOutput(out: string): SprayCredential[] {
  const found: SprayCredential[] = [];
  const seen = new Set<string>();
  for (const line of out.split("\n")) {
    const m = line.match(/^\[\d+\]\[[^\]]+\]\s+host:\s+\S+\s+login:\s+(.*?)\s+password:\s+(.*?)\s*$/);
    if (!m) continue;
    const key = `${m[1]}:${m[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    found.push({ login: m[1], password: m[2] });
  }
  return found;
}

export async function runCredentialSpray(targetUrl: string): Promise<CredentialSprayResult> {
  const login = process.env.CREDENTIAL_SPRAY_LOGIN;
  const wordlist = process.env.CREDENTIAL_SPRAY_WORDLIST;
  const form = process.env.CREDENTIAL_SPRAY_FORM;
  // All three owner-supplied inputs must be present. Without any one, the tool
  // cannot run safely (no designated test account / no login shape), so it
  // no-ops — the default state until the owner deliberately configures it.
  if (!login || !wordlist || !form) return { status: "not_configured" };

  let host: string;
  let port: string;
  let scheme: string;
  try {
    const u = new URL(targetUrl);
    host = u.hostname;
    scheme = u.protocol === "https:" ? "https-post-form" : "http-post-form";
    port = u.port || (u.protocol === "https:" ? "443" : "80");
  } catch {
    return { status: "error", note: "Invalid URL" };
  }

  const outFile = join(tmpdir(), `hydra-${Date.now()}-${process.pid}.out`);
  try {
    await execTool(
      "hydra",
      [
        "-l", login, // ONE designated test account, never a user list
        "-P", wordlist,
        "-f", // stop at the first success
        "-t", "1", // low parallelism — lockout-avoidance
        "-o", outFile,
        host,
        "-s", port,
        scheme,
        form,
      ],
      { timeout: HYDRA_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );
    const raw = await readFile(outFile, "utf8").catch(() => "");
    return { status: "completed", found: parseHydraOutput(raw) };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") return { status: "not_configured" };
    // hydra exits non-zero when it finds nothing with -f; that is a normal
    // "no weak credential" result, not an error, so read the file anyway.
    const raw = await readFile(outFile, "utf8").catch(() => "");
    if (raw.includes("# Hydra")) return { status: "completed", found: parseHydraOutput(raw) };
    return { status: "error", note: `hydra exited with error: ${error.message}` };
  } finally {
    rm(outFile, { force: true }).catch(() => undefined);
  }
}

/**
 * A recovered credential means the designated test account accepted a password
 * from the spray list without being locked out or throttled — a high-severity
 * demonstration that the login is exposed to credential attacks. The password
 * is the owner's own sacrificial test account, surfaced so they can see which
 * weak password got in; keyed by login so it rides findingsDiff.ts.
 */
export function buildCredentialSprayFindings(found: SprayCredential[]): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const c of found) {
    if (seen.has(c.login)) continue;
    seen.add(c.login);
    findings.push({
      checkId: `credential-spray.weak-credential:${c.login}`,
      severity: "high",
      title: `Login accepted a sprayed password for test account "${c.login}"`,
      detail: `The designated test account "${c.login}" authenticated with the password "${c.password}" from the authorised spray list — the login endpoint neither locked the account nor throttled the attempts. Treat this as a demonstration that credential-stuffing / brute-force attacks are not defended here.`,
      remediation: `Add account lockout and/or rate limiting on failed logins, require strong passwords (block known-breached and common passwords), and offer multi-factor authentication. This was your own designated test account; real accounts face the same exposure.`,
    });
  }
  return findings;
}
