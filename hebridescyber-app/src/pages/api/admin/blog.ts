import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "./_auth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  // GET  /api/admin/blog?status=draft|published&search=&page=
  if (req.method === "GET") {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
    const pageSize = 20;
    const offset = (page - 1) * pageSize;

    let query = supabaseAdmin
      .from("blog_posts")
      .select("id, slug, title, excerpt, author_id, status, published_at, created_at, updated_at, tags, cover_image_url", { count: "exact" })
      .order("updated_at", { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (status) query = query.eq("status", status);
    if (search) query = query.ilike("title", `%${search}%`);

    const { data, error, count } = await query;
    if (error) return res.status(500).json({ error: error.message });

    return res.status(200).json({ posts: data ?? [], total: count ?? 0, page, pageSize });
  }

  // POST /api/admin/blog — create new post
  if (req.method === "POST") {
    const { title, slug, excerpt, body, tags, status, cover_image_url } = req.body as {
      title?: string;
      slug?: string;
      excerpt?: string;
      body?: string;
      tags?: string[];
      status?: "draft" | "published";
      cover_image_url?: string;
    };

    if (!title || !slug) return res.status(400).json({ error: "title and slug are required" });

    const { data, error } = await supabaseAdmin
      .from("blog_posts")
      .insert({
        title,
        slug,
        excerpt: excerpt ?? "",
        body: body ?? "",
        tags: tags ?? [],
        status: status ?? "draft",
        cover_image_url: cover_image_url ?? null,
        author_id: adminId,
        published_at: status === "published" ? new Date().toISOString() : null,
      })
      .select("id, slug")
      .single();

    if (error) return res.status(400).json({ error: error.message });
    return res.status(201).json(data);
  }

  return res.status(405).end();
}
