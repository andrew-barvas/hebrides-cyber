import type { NextApiRequest, NextApiResponse } from "next";
import { createClient } from "@supabase/supabase-js";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary } from "@/lib/scanners";
import { validateNoSsrf, hostnameFromUrl } from "@/lib/ownership";
import { checkRateLimit } from "@/lib/rateLimit";

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

const serviceToken = process.env.GITHUB_ACTIONS_TOKEN ?? "";
const allowDevToken = (process.env.ALLOW_DEV_TOKEN_VERIFICATION ?? "true") === "true";

// Disable Next.js body size limit — scan results can be large.
export const config = { api: { bodyParser: { sizeLimit: "1mb" } } };

async function resolveCaller(req: NextApiRequest): Promise<{ ownerId: string; isService: boolean } | null> {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const { data, error } = await supabaseAdmin.auth.getUser(auth.slice(7));
    if (error || !data.user) return null;
    return { ownerId: data.user.id, isService: false };
  }
  const provided = req.headers["x-service-token"];
  if (provided && serviceToken && provided === serviceToken) {
    const owner = req.body?.owner as string | undefined;
    if (!owner) return null;
    return { ownerId: owner, isService: true };
  }
  return null;
}

async function isOwnershipVerified(
  ownerId: string,
  targetUrl: string,
  proofToken: string,
  req: NextApiRequest
): Promise<boolean> {
  let domain: string;
  try { domain = hostnameFromUrl(targetUrl); } catch { return false; }

  const { data } = await supabaseAdmin
    .from("verifications")
    .select("verified_at")
    .eq("owner", ownerId)
    .eq("domain", domain)
    .maybeSingle();
  if (data?.verified_at) return true;

  if (!allowDevToken) return false;

  const supplied = (req.headers["x-scan-token"] as string | undefined) ?? (req.query.verification as string | undefined);
  if (!supplied) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(proofToken);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await resolveCaller(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization" });

  const limit = await checkRateLimit(caller.ownerId);
  if (!limit.allowed) {
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const { targetUrl, scanId } = req.body as { targetUrl?: string; scanId?: string };

  // ── Step 1: create scan row, return proof token ───────────────────────────
  if (!scanId) {
    if (!targetUrl) return res.status(400).json({ error: "targetUrl is required" });

    try { await validateNoSsrf(targetUrl); }
    catch (err) { return res.status(400).json({ error: `Invalid target: ${(err as Error).message}` }); }

    const proofToken = randomBytes(16).toString("hex");
    const { data: scan, error } = await supabaseAdmin
      .from("scans")
      .insert({ owner: caller.ownerId, target_url: targetUrl, status: "pending", proof_token: proofToken, owner_verified: false })
      .select("id")
      .single();

    if (error || !scan) return res.status(500).json({ error: error?.message ?? "Failed to create scan" });

    return res.status(200).json({
      scanId: scan.id,
      proofToken,
      status: "awaiting_verification",
    });
  }

  // ── Step 2: verify ownership, run scan ────────────────────────────────────
  const { data: scan, error: fetchErr } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, proof_token, status")
    .eq("id", scanId)
    .maybeSingle();

  if (fetchErr || !scan) return res.status(404).json({ error: "Scan not found" });
  if (!caller.isService && scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  if (!(await isOwnershipVerified(scan.owner, scan.target_url, scan.proof_token, req))) {
    return res.status(401).json({
      error: "Ownership not verified. Supply the X-Scan-Token header with the proofToken from step 1.",
    });
  }

  try { await validateNoSsrf(scan.target_url); }
  catch (err) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return res.status(400).json({ error: `SSRF check failed: ${(err as Error).message}` });
  }

  await supabaseAdmin.from("scans").update({ status: "running", owner_verified: true }).eq("id", scanId);

  const results = await runAllChecks(scan.target_url);
  const { findings } = summariseResults(results);
  const score = scoreFromFindings(findings);
  const summary = await generateAiSummary(results, findings);

  const { error: insertErr } = await supabaseAdmin.from("scan_results").insert({
    scan_id: scanId,
    results: { ...results, findings },
    summary,
    score,
  });

  if (insertErr) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return res.status(500).json({ error: insertErr.message });
  }

  await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scanId);

  return res.status(200).json({ ok: true, scanId, status: "completed", score, summary });
}
