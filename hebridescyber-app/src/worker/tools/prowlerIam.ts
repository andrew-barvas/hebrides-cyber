// Prowler (Apache-2.0) IAM posture, run read-only against a customer's AWS
// account. Covers what cloudPosture.ts does not: IAM policies that allow
// privilege escalation, administrator-equivalent grants, root/user MFA.
// Only Prowler's `iam` service runs (`-s iam`: every iam_* check, including
// iam_policy_allows_privilege_escalation and the inline-policy variant); no
// other service is touched.
//
// Access is a customer-created cross-account role (SecurityAudit +
// ViewOnlyAccess) that Prowler assumes with an external id we generated for
// that account (aws-role-credential.ts). We never hold the customer's
// long-lived keys. The platform's own caller identity comes from
// PROWLER_AWS_ACCESS_KEY_ID / PROWLER_AWS_SECRET_ACCESS_KEY (deliberately not
// the ambient AWS_* names, so a stray runner credential is never used).
// Prowler's checks are List/Get/Describe calls only.
//
// Evidence discipline: a run that did not produce a parseable report for the
// right account is `error`, never an empty "completed" — findingLifecycle.ts
// reads a completed run's silence as "fixed". A missing platform credential or
// binary is also `error` once the owner has connected a role, because they
// expect the check to be running.
//
// Parsing follows Prowler 5.47.0's `json-ocsf` output (OCSF Detection
// Finding), see fixtures/prowler/README.md.
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SupabaseClient } from "@supabase/supabase-js";
import { execTool } from "../../lib/execTool";
import { decryptCredentials } from "../../lib/credentialEncryption";
import { planGate } from "../../lib/planAccess";
import type { Finding } from "../../lib/scanners";
import { PROWLER_IAM_FALLBACK_REMEDIATION } from "../../lib/scanners/remediationText";

const PROWLER_TIMEOUT_MS = 15 * 60_000;
const OUTPUT_NAME = "prowler-iam";
const ROLE_ARN_RE = /^arn:aws:iam::(\d{12}):role\/[\w+=,.@/-]{1,512}$/;

export type ProwlerAccountRun = { accountId: string; label: string; checksEvaluated: number; failed: number };

export type ProwlerIamResult =
  | { status: "completed"; findings: Finding[]; accounts: ProwlerAccountRun[] }
  | { status: "not_configured"; note: string; findings: Finding[] }
  | { status: "not_applicable"; note: string; findings: Finding[] }
  | { status: "error"; note: string; findings: Finding[]; accounts: ProwlerAccountRun[] };

type OcsfRecord = {
  status_code?: string;
  status_detail?: string;
  severity?: string;
  risk_details?: string;
  finding_info?: { uid?: string; title?: string; desc?: string };
  remediation?: { desc?: string; references?: string[] };
  resources?: Array<{ uid?: string; name?: string; type?: string; region?: string }>;
  metadata?: { event_code?: string; product?: { version?: string } };
  cloud?: { account?: { uid?: string } };
  unmapped?: { related_url?: string };
};

export type ProwlerRecord = {
  checkId: string;
  status: "PASS" | "FAIL" | "MANUAL" | "MUTED" | string;
  severity: Finding["severity"];
  accountId: string;
  resourceUid: string;
  resourceName: string;
  resourceType: string;
  region: string;
  title: string;
  statusDetail: string;
  risk: string;
  remediation: string;
  reference: string;
  prowlerVersion: string;
  findingUid: string;
};

const SEVERITY: Record<string, Finding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "info",
  info: "info",
};

/**
 * Pure: the text of Prowler's `.ocsf.json` report to its records. Throws on
 * anything that isn't a JSON array of objects, and on a record with no check
 * id or account, so a malformed report is an error upstream, never "no
 * findings".
 */
export function parseProwlerOcsf(text: string): ProwlerRecord[] {
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed)) throw new Error("Prowler report is not a JSON array");
  return (parsed as OcsfRecord[]).map((r, i) => {
    const checkId = r.metadata?.event_code;
    const accountId = r.cloud?.account?.uid;
    if (!checkId || !accountId || typeof r.status_code !== "string") {
      throw new Error(`Prowler report record ${i} is missing check id, account or status`);
    }
    const res = r.resources?.[0];
    return {
      checkId,
      status: r.status_code.toUpperCase(),
      severity: SEVERITY[(r.severity ?? "").toLowerCase()] ?? "info",
      accountId,
      resourceUid: res?.uid || res?.name || "account",
      resourceName: res?.name ?? "",
      resourceType: res?.type ?? "",
      region: res?.region ?? "",
      title: r.finding_info?.title ?? checkId,
      statusDetail: r.status_detail ?? "",
      risk: r.risk_details ?? "",
      remediation: r.remediation?.desc ?? "",
      reference: r.remediation?.references?.[0] ?? r.unmapped?.related_url ?? "",
      prowlerVersion: r.metadata?.product?.version ?? "",
      findingUid: r.finding_info?.uid ?? "",
    };
  });
}

/** Pure: only FAIL records become findings. PASS/MANUAL/MUTED prove nothing is wrong or are not ours to call. */
export function prowlerRecordsToFindings(records: ProwlerRecord[]): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const r of records) {
    if (r.status !== "FAIL") continue;
    const checkId = `prowler.${r.checkId}:${r.accountId}:${r.resourceUid}`;
    if (seen.has(checkId)) continue;
    seen.add(checkId);
    findings.push({
      checkId,
      severity: r.severity,
      title: `[Prowler] ${r.title}`,
      detail: `${r.statusDetail}${r.risk ? ` Risk: ${r.risk}` : ""}`.trim(),
      remediation: r.remediation ? `${r.remediation}${r.reference ? ` See ${r.reference}.` : ""}` : PROWLER_IAM_FALLBACK_REMEDIATION,
      metadata: {
        prowler: {
          check: r.checkId,
          version: r.prowlerVersion,
          accountId: r.accountId,
          resourceUid: r.resourceUid,
          resourceType: r.resourceType,
          region: r.region,
          findingUid: r.findingUid,
          status: r.status,
        },
      },
    });
  }
  return findings;
}

type RoleCredential = { label: string; roleArn: string; externalId: string };

/** The owner's connected roles. Rows still waiting for a role ARN, and legacy access-key rows, are not runnable. */
async function loadRoles(supabaseAdmin: SupabaseClient, ownerId: string): Promise<{ roles: RoleCredential[]; pending: number; undecryptable: number }> {
  const { data, error } = await supabaseAdmin
    .from("cloud_credentials")
    .select("label, credentials_encrypted")
    .eq("owner", ownerId)
    .eq("provider", "aws");
  if (error) throw new Error(`Could not read cloud credentials: ${error.message}`);
  const roles: RoleCredential[] = [];
  let pending = 0;
  let undecryptable = 0;
  for (const row of data ?? []) {
    let c: Record<string, string>;
    try {
      c = decryptCredentials(row.credentials_encrypted);
    } catch {
      undecryptable++;
      continue;
    }
    if (c.authMode !== "role") continue;
    if (!c.roleArn) {
      pending++;
      continue;
    }
    roles.push({ label: row.label, roleArn: c.roleArn, externalId: c.externalId });
  }
  return { roles, pending, undecryptable };
}

function scrub(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) if (s) out = out.split(s).join("[redacted]");
  return out.slice(0, 500);
}

async function runForRole(role: RoleCredential, platformEnv: Record<string, string>): Promise<{ records: ProwlerRecord[]; accountId: string }> {
  const m = ROLE_ARN_RE.exec(role.roleArn);
  if (!m || !role.externalId) throw new Error(`role "${role.label}" has an invalid role ARN or no external id`);
  const dir = await mkdtemp(join(tmpdir(), "prowler-iam-"));
  try {
    try {
      await execTool(
        "prowler",
        [
          "aws",
          "--role", role.roleArn,
          "--external-id", role.externalId,
          "--session-duration", "3600",
          "--role-session-name", "HebridesCyberIamPosture",
          "--service", "iam",
          "--output-formats", "json-ocsf",
          "--output-directory", dir,
          "--output-filename", OUTPUT_NAME,
          // Failed checks exit 3 by default, which execFile would report as a crash.
          "--ignore-exit-code-3",
          "--no-banner",
        ],
        { timeout: PROWLER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024, env: platformEnv as NodeJS.ProcessEnv }
      );
    } catch (err) {
      const e = err as NodeJS.ErrnoException & { stderr?: string };
      if (e.code === "ENOENT") throw new Error("prowler is not installed on this worker");
      throw new Error(`prowler failed: ${scrub(`${e.message} ${e.stderr ?? ""}`, [role.externalId])}`);
    }
    let text: string;
    try {
      text = await readFile(join(dir, `${OUTPUT_NAME}.ocsf.json`), "utf8");
    } catch {
      throw new Error("prowler produced no report (the role could not be assumed or no check ran)");
    }
    const records = parseProwlerOcsf(text);
    // A report for a different account than the role names is not evidence about this one.
    if (records.some((r) => r.accountId !== m[1])) throw new Error(`prowler reported on an account other than ${m[1]}`);
    // The iam service always evaluates something (root MFA at minimum); nothing
    // at all means the run saw nothing, which is not the same as a clean account.
    if (records.length === 0) throw new Error("prowler evaluated no IAM checks");
    return { records, accountId: m[1] };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function runProwlerIam(supabaseAdmin: SupabaseClient, ownerId: string): Promise<ProwlerIamResult> {
  try {
    // Same tier that gates saving cloud credentials (account/cloud-credentials.ts).
    const gate = await planGate(supabaseAdmin, ownerId, "agency");
    if (gate === "error") return { status: "error", note: "Could not check the plan tier", findings: [], accounts: [] };
    if (gate === "denied") return { status: "not_applicable", note: "Cloud posture scanning is an Agency-plan feature", findings: [] };

    const { roles, pending, undecryptable } = await loadRoles(supabaseAdmin, ownerId);
    if (roles.length === 0) {
      if (undecryptable > 0) return { status: "error", note: "Stored AWS credentials could not be decrypted (CREDENTIALS_ENC_KEY missing or rotated)", findings: [], accounts: [] };
      return {
        status: "not_configured",
        note: pending > 0 ? "An AWS role connection is waiting for its role ARN" : "No AWS cross-account role connected",
        findings: [],
      };
    }

    const keyId = process.env.PROWLER_AWS_ACCESS_KEY_ID;
    const secret = process.env.PROWLER_AWS_SECRET_ACCESS_KEY;
    if (!keyId || !secret) {
      return { status: "error", note: "Platform AWS identity for assuming customer roles is not configured (PROWLER_AWS_ACCESS_KEY_ID / PROWLER_AWS_SECRET_ACCESS_KEY)", findings: [], accounts: [] };
    }
    // Only what Prowler needs; the worker's other secrets (service role key, etc.) stay out of its environment.
    const platformEnv: Record<string, string> = {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      AWS_ACCESS_KEY_ID: keyId,
      AWS_SECRET_ACCESS_KEY: secret,
      AWS_DEFAULT_REGION: "us-east-1",
    };

    const findings: Finding[] = [];
    const accounts: ProwlerAccountRun[] = [];
    const errors: string[] = [];
    for (const role of roles) {
      try {
        const { records, accountId } = await runForRole(role, platformEnv);
        const f = prowlerRecordsToFindings(records);
        findings.push(...f);
        accounts.push({ accountId, label: role.label, checksEvaluated: new Set(records.map((r) => r.checkId)).size, failed: f.length });
      } catch (err) {
        errors.push(`${role.label}: ${(err as Error).message}`);
      }
    }
    if (errors.length > 0) return { status: "error", note: errors.join("; "), findings, accounts };
    return { status: "completed", findings, accounts };
  } catch (err) {
    return { status: "error", note: (err as Error).message, findings: [], accounts: [] };
  }
}
