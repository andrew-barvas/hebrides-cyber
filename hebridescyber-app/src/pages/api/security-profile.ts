// /api/security-profile — the owner publishes, looks up or removes the public
// security profile for one of their verified sites (src/lib/securityProfile.ts).
//   GET    ?targetUrl=…        → { slug | null }
//   POST   { targetUrl }       → { slug }   (publishing again keeps the slug)
//   DELETE { targetUrl }       → { removed: true }  (the link stops working)
// Session only, like share links: a profile is a deliberate, visible choice.
// Publishing needs a verified domain, so nobody can publish a profile for a
// site they don't control.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { isDomainVerified } from "@/lib/ownership";
import { hostOf } from "@/lib/findingLifecycle";
import { newProfileSlug } from "@/lib/securityProfile";

const bodySchema = z.object({ targetUrl: z.string().url() });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Security profiles can only be managed from a logged-in session." });

  const targetUrl = req.method === "GET" ? String(req.query.targetUrl ?? "") : (parseBody(bodySchema, req.body, res)?.targetUrl ?? null);
  if (targetUrl === null) return; // parseBody answered 400
  const host = hostOf(targetUrl);
  if (!host) return res.status(400).json({ error: "targetUrl must be a website address" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin.from("security_profiles").select("slug").eq("owner", caller.ownerId).eq("target_host", host).maybeSingle();
    if (error) return respondInternalError(res, "security-profile", error);
    return res.status(200).json({ slug: (data as { slug?: string } | null)?.slug ?? null });
  }

  if (req.method === "POST") {
    if (!(await isDomainVerified(supabaseAdmin, caller.ownerId, targetUrl))) {
      return res.status(403).json({ error: "Verify you own this domain before publishing a profile for it." });
    }
    const { data: existing, error: readError } = await supabaseAdmin.from("security_profiles").select("slug").eq("owner", caller.ownerId).eq("target_host", host).maybeSingle();
    if (readError) return respondInternalError(res, "security-profile", readError);
    if (existing) return res.status(200).json({ slug: (existing as { slug: string }).slug });
    const slug = newProfileSlug();
    const { error } = await supabaseAdmin.from("security_profiles").insert({ owner: caller.ownerId, target_host: host, slug });
    if (error) return respondInternalError(res, "security-profile", error);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "security_profile.published", resourceType: "security_profile", resourceId: host, metadata: { host } });
    return res.status(201).json({ slug });
  }

  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin.from("security_profiles").delete().eq("owner", caller.ownerId).eq("target_host", host);
    if (error) return respondInternalError(res, "security-profile", error);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "security_profile.removed", resourceType: "security_profile", resourceId: host, metadata: { host } });
    return res.status(200).json({ removed: true });
  }

  res.setHeader("Allow", "GET, POST, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
}
