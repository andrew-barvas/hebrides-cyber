// POST/DELETE /api/account/connect-repo — customer-facing half of the
// dependency-manifest-scanning feature: lets an account owner tell us which
// GitHub repo to scan, verifying (once, at connect time) that the Hebrides
// Cyber bot can actually reach it before we ever write a row.
//
// Follows the GitHub-integration precedent set by
// src/pages/api/generate-fix-pr.ts: shared GITHUB_PAT env var, the same
// `owner/repo` validation regex, and the same collaborator precondition —
// the customer must add the bot account as a collaborator before connecting.
//
// Writes go through supabaseAdmin (service role) because
// sql/migrations/009_repo_connections.sql deliberately ships with no
// insert/update/delete RLS policy: this route is the only place a row in
// repo_connections is allowed to be written, and only after the GitHub
// access check below returns 200. Reads don't need a route at all — the
// table's own owner-scoped SELECT policy lets the account page query
// repo_connections directly via the browser's session, the same way
// src/app/account/page.tsx already reads `subscriptions` directly.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

const githubPat = process.env.GITHUB_PAT ?? "";
const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;

function ghHeaders() {
  return {
    Authorization: `Bearer ${githubPat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Unset PAT is a deployment gap, not a client error and not a crash.
  if (!githubPat) {
    return res.status(503).json({ error: "GITHUB_PAT is not configured on this deployment — see .env.example." });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Repository connections can only be managed from a logged-in session, not with an API key." });
  }

  const { githubRepo } = req.body as { githubRepo?: string };
  if (!githubRepo || !/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return res.status(400).json({ error: "githubRepo must look like 'owner/repo'" });
  }

  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin
      .from("repo_connections")
      .delete()
      .eq("owner", caller.ownerId)
      .eq("github_repo", githubRepo);

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  // POST — verify the bot can actually reach the repo before writing
  // anything. Cheap and real evidence that access exists, rather than
  // trusting the input string blindly.
  let accessRes: Response;
  try {
    accessRes = await fetch(`${githubApi}/repos/${githubRepo}`, {
      headers: ghHeaders(),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
  } catch (err) {
    return res.status(502).json({ error: `Could not reach GitHub: ${(err as Error).message}` });
  }

  if (accessRes.status === 404) {
    return res.status(400).json({
      error: `GitHub returned 404 for ${githubRepo}. Either the repository doesn't exist, or the Hebrides Cyber bot hasn't been added as a collaborator yet — add it first, then try again.`,
    });
  }
  if (!accessRes.ok) {
    return res.status(400).json({ error: `GitHub returned ${accessRes.status} for ${githubRepo} — check the repo name and that the bot has access.` });
  }

  // unique(owner, github_repo) makes this idempotent — reconnecting the same
  // repo (e.g. after the bot was re-added) never errors on a duplicate row.
  const { error } = await supabaseAdmin
    .from("repo_connections")
    .upsert({ owner: caller.ownerId, github_repo: githubRepo }, { onConflict: "owner,github_repo" });

  if (error) return res.status(500).json({ error: error.message });
  return res.status(200).json({ ok: true, githubRepo });
}
