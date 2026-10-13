import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { parseBody } from "@/lib/validate";

const createPostSchema = z
  .object({
    title: z.string().min(1, "title is required"),
    slug: z.string().min(1, "slug is required"),
    excerpt: z.string().optional(),
    body: z.string().optional(),
    tags: z.array(z.string()).optional(),
    status: z.enum(["draft", "published", "scheduled"]).optional(),
    // Only meaningful (and required) when status is "scheduled" — see the refine below.
    published_at: z.string().optional(),
    cover_image_url: z.string().url().nullish(),
  })
  .refine((data) => data.status !== "scheduled" || isFutureDate(data.published_at), {
    message: 'must be a valid future date when status is "scheduled"',
    path: ["published_at"],
  });

function isFutureDate(value: string | undefined): boolean {
  if (!value) return false;
  const t = Date.parse(value);
  return Number.isFinite(t) && t > Date.now();
}

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
    const parsed = parseBody(createPostSchema, req.body, res);
    if (!parsed) return;
    const { title, slug, excerpt, body, tags, status, published_at, cover_image_url } = parsed;

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
        published_at: status === "published" ? new Date().toISOString() : status === "scheduled" ? new Date(published_at!).toISOString() : null,
      })
      .select("id, slug")
      .single();

    if (error) return res.status(400).json({ error: error.message });
    return res.status(201).json(data);
  }

  return res.status(405).end();
}
