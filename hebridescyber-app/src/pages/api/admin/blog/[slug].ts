import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const slug = typeof req.query.slug === "string" ? req.query.slug : null;
  if (!slug) return res.status(400).json({ error: "slug is required" });

  // GET /api/admin/blog/[slug] — fetch full post including body
  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("blog_posts")
      .select("*")
      .eq("slug", slug)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Post not found" });
    return res.status(200).json(data);
  }

  // PATCH /api/admin/blog/[slug] — update post fields
  if (req.method === "PATCH") {
    const allowed = ["title", "slug", "excerpt", "body", "tags", "status", "cover_image_url", "meta_description", "og_image"] as const;
    type Field = (typeof allowed)[number];
    const updates: Partial<Record<Field, unknown>> & { published_at?: string | null } = {};

    for (const field of allowed) {
      if (field in req.body) updates[field] = req.body[field];
    }
    if (updates.status === "published") {
      const { data: existing } = await supabaseAdmin
        .from("blog_posts")
        .select("published_at, status")
        .eq("slug", slug)
        .maybeSingle();
      if (existing?.status !== "published") {
        updates.published_at = new Date().toISOString();
      }
    } else if (updates.status === "draft") {
      updates.published_at = null;
    } else if (updates.status === "scheduled") {
      const publishedAt = typeof req.body.published_at === "string" ? req.body.published_at : null;
      const t = publishedAt ? Date.parse(publishedAt) : NaN;
      if (!Number.isFinite(t) || t <= Date.now()) {
        return res.status(400).json({ error: 'published_at must be a valid future date when status is "scheduled"' });
      }
      updates.published_at = new Date(t).toISOString();
    }
    updates["updated_at" as Field] = new Date().toISOString();

    const { data, error } = await supabaseAdmin
      .from("blog_posts")
      .update(updates)
      .eq("slug", slug)
      .select("id, slug, status, updated_at")
      .single();

    if (error) return res.status(400).json({ error: error.message });
    return res.status(200).json(data);
  }

  // DELETE /api/admin/blog/[slug] — permanently delete a post
  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin.from("blog_posts").delete().eq("slug", slug);
    if (error) return res.status(400).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).end();
}
