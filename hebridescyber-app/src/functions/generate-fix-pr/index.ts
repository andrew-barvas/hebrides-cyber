// Azure Function (HTTP trigger): generate-fix-pr
//
// The "fix it" half of the product, scoped responsibly: turns a scan's
// findings into a real GitHub pull request adding a concrete
// SECURITY-FIXES.md with copy-pasteable snippets (src/lib/remediation.ts),
// rather than silently rewriting the customer's live config. A human still
// reviews and merges — that's the point, not a limitation.
//
// Requires GITHUB_PAT (a fine-grained personal access token, or a GitHub
// App installation token — see TODO below) with contents:write and
// pull-requests:write on whichever repos it's used against. The customer
// must add the Hebrides Cyber bot account/App as a collaborator first.
//
// TODO: a shared PAT across all customers is a real blast-radius risk if
// it leaks — before onboarding real customers, replace this with a GitHub
// App (per-installation tokens, scoped to only the repos each customer
// explicitly installs it on) rather than one long-lived PAT for everyone.

import { createClient } from "@supabase/supabase-js";
import { buildRemediationMarkdown } from "../../lib/remediation";
import type { Finding } from "../../lib/scanners";

type HttpRequest = {
  headers: Record<string, string | undefined>;
  body: { scanId?: string; githubRepo?: string; baseBranch?: string };
};
type HttpResponseInit = { status: number; jsonBody: unknown };

const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);
const githubPat = process.env.GITHUB_PAT ?? "";
const githubApi = "https://api.github.com";

function ghHeaders() {
  return {
    Authorization: `Bearer ${githubPat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

export default async function generateFixPr(req: HttpRequest): Promise<HttpResponseInit> {
  if (!githubPat) {
    return { status: 501, jsonBody: { error: "GITHUB_PAT is not configured on this Function — see .env.example." } };
  }

  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) {
    return { status: 401, jsonBody: { error: "Missing Authorization Bearer token" } };
  }
  const { data: userData, error: authError } = await supabaseAdmin.auth.getUser(
    authHeader.slice("Bearer ".length)
  );
  if (authError || !userData.user) {
    return { status: 401, jsonBody: { error: "Invalid session" } };
  }

  const { scanId, githubRepo, baseBranch = "main" } = req.body;
  if (!scanId || !githubRepo) {
    return { status: 400, jsonBody: { error: "scanId and githubRepo ('owner/repo') are required" } };
  }
  if (!/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: 400, jsonBody: { error: "githubRepo must look like 'owner/repo'" } };
  }

  const { data: scan, error: scanError } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url")
    .eq("id", scanId)
    .maybeSingle();
  if (scanError || !scan) {
    return { status: 404, jsonBody: { error: "Scan not found" } };
  }
  if (scan.owner !== userData.user.id) {
    return { status: 403, jsonBody: { error: "You do not own this scan" } };
  }

  const { data: result, error: resultError } = await supabaseAdmin
    .from("scan_results")
    .select("results, score")
    .eq("scan_id", scanId)
    .maybeSingle();
  if (resultError || !result) {
    return { status: 404, jsonBody: { error: "No results for this scan yet" } };
  }

  const findings = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const markdown = buildRemediationMarkdown(scan.target_url, findings, result.score ?? null);

  try {
    const prUrl = await openRemediationPr(githubRepo, baseBranch, scanId, markdown);
    return { status: 200, jsonBody: { ok: true, prUrl } };
  } catch (err) {
    return { status: 502, jsonBody: { error: `GitHub API error: ${(err as Error).message}` } };
  }
}

async function openRemediationPr(
  repo: string,
  baseBranch: string,
  scanId: string,
  markdown: string
): Promise<string> {
  // 1. Get the SHA of the base branch's HEAD commit.
  const baseRefRes = await fetch(`${githubApi}/repos/${repo}/git/ref/heads/${baseBranch}`, { headers: ghHeaders() });
  if (!baseRefRes.ok) throw new Error(`could not read base branch (${baseRefRes.status}) — check GITHUB_PAT access to ${repo}`);
  const baseRef = (await baseRefRes.json()) as { object: { sha: string } };

  // 2. Create a new branch from that commit.
  const branchName = `hebridescyber/security-fixes-${scanId.slice(0, 8)}`;
  const createRefRes = await fetch(`${githubApi}/repos/${repo}/git/refs`, {
    method: "POST",
    headers: ghHeaders(),
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: baseRef.object.sha }),
  });
  if (!createRefRes.ok && createRefRes.status !== 422) {
    // 422 usually means the branch already exists (e.g. re-running for the same scan) — safe to continue.
    throw new Error(`could not create branch (${createRefRes.status})`);
  }

  // 3. Create (or update) SECURITY-FIXES.md on that branch.
  const path = "SECURITY-FIXES.md";
  const existingRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}?ref=${branchName}`, {
    headers: ghHeaders(),
  });
  const existingSha = existingRes.ok ? ((await existingRes.json()) as { sha: string }).sha : undefined;

  const putRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}`, {
    method: "PUT",
    headers: ghHeaders(),
    body: JSON.stringify({
      message: "Add Hebrides Cyber security fix recommendations",
      content: Buffer.from(markdown, "utf-8").toString("base64"),
      branch: branchName,
      ...(existingSha ? { sha: existingSha } : {}),
    }),
  });
  if (!putRes.ok) throw new Error(`could not write ${path} (${putRes.status})`);

  // 4. Open the PR (or return the existing one if it's already open).
  const prRes = await fetch(`${githubApi}/repos/${repo}/pulls`, {
    method: "POST",
    headers: ghHeaders(),
    body: JSON.stringify({
      title: "Security fixes from Hebrides Cyber scan",
      head: branchName,
      base: baseBranch,
      body: "Automated remediation suggestions — see SECURITY-FIXES.md. Nothing else in this repo was touched.",
    }),
  });
  if (prRes.status === 422) {
    // Likely "already exists" — find and return it instead of failing.
    const listRes = await fetch(`${githubApi}/repos/${repo}/pulls?head=${repo.split("/")[0]}:${branchName}`, {
      headers: ghHeaders(),
    });
    const list = (await listRes.json()) as Array<{ html_url: string }>;
    if (list[0]) return list[0].html_url;
    throw new Error("PR creation returned 422 and no existing PR was found");
  }
  if (!prRes.ok) throw new Error(`could not open PR (${prRes.status})`);
  const pr = (await prRes.json()) as { html_url: string };
  return pr.html_url;
}
