// POST /api/v1/dependency-diff — the vulnerable packages a pull request
// introduces (E-71). Takes a lockfile's content on the PR's base and head and
// returns only what head adds that OSV.dev knows to be vulnerable.
//
// Stateless: nothing is stored and no repository access is needed — the
// caller (the packaged Action, or any CI) supplies the file contents. Pro and
// Agency plans; API key or session auth; rate limited per account.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { hasProAccess } from "@/lib/planAccess";
import { computeDependencyDiff, MAX_DIFF_FILES, MAX_TOTAL_CHARS } from "@/lib/dependencyDiff";

const MAX_FILE_CHARS = 5_000_000;
const content = z.string().max(MAX_FILE_CHARS).nullable().optional();

const schema = z.object({
  files: z
    .array(
      z.object({
        name: z.string().min(1).max(300),
        base: content,
        head: content,
        base_companion: content,
        head_companion: content,
      })
    )
    .min(1, "at least one lockfile is required")
    .max(MAX_DIFF_FILES, `at most ${MAX_DIFF_FILES} lockfiles per request`),
}).refine(
  (body) => body.files.reduce((sum, f) => sum + (f.base?.length ?? 0) + (f.head?.length ?? 0) + (f.base_companion?.length ?? 0) + (f.head_companion?.length ?? 0), 0) <= MAX_TOTAL_CHARS,
  { message: `lockfile contents total more than ${MAX_TOTAL_CHARS / 1_000_000} MB`, path: ["files"] }
);

export const config = { api: { bodyParser: { sizeLimit: "25mb" } } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header. Use: Authorization: Bearer <api-key>" });

  if (!(await hasProAccess(supabaseAdmin, caller.ownerId))) {
    return res.status(403).json({ error: "Pull-request dependency checks need a Pro or Agency plan.", code: "plan_required" });
  }

  const limit = await checkRateLimit(caller.ownerId, "dependency-diff");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds ?? 60));
    return res.status(429).json({ error: "Rate limit exceeded", retry_after_seconds: limit.retryAfterSeconds });
  }

  const parsed = parseBody(schema, req.body, res);
  if (!parsed) return;

  const result = await computeDependencyDiff(
    parsed.files.map((f) => ({
      name: f.name,
      base: f.base ?? null,
      head: f.head ?? null,
      base_companion: f.base_companion ?? null,
      head_companion: f.head_companion ?? null,
    }))
  );
  // OSV.dev being unreachable is "we don't know", not "clean": a 502 the CI
  // step can distinguish from a pass.
  if (result.status === "error") return res.status(502).json({ error: `Vulnerability lookup failed: ${result.error}`, code: "lookup_failed" });
  return res.status(200).json(result);
}
