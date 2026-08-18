// POST /api/generate-daily-blog — drafts and publishes the daily cyber
// security blog post (see src/lib/newsletter.ts's generateDailyBlogPost).
// Distinct from src/pages/api/generate-newsletter.ts, which publishes the
// separate WEEKLY newsletter — the two share the same underlying real-event
// sourcing (CISA KEV / NVD / security-news RSS) but different lookback
// windows, framing, and slugs, so they never collide even when both run on
// the same day. Triggered by .github/workflows/daily-blog.yml on a cron.
// Gated behind X-Service-Token (NEWSLETTER_SERVICE_TOKEN — same shared
// secret as the weekly route; both write the same kind of public-facing
// content, so one token covers both) since this should not be callable by
// just anyone who finds the URL. Not named GITHUB_ACTIONS_TOKEN — GitHub
// rejects any repo secret starting with GITHUB_ as reserved for its own
// auto-generated ones.
import type { NextApiRequest, NextApiResponse } from "next";
import { generateDailyBlogPost } from "@/lib/newsletter";
import { supabaseAdmin } from "@/lib/apiAuth";

const serviceToken = process.env.NEWSLETTER_SERVICE_TOKEN ?? "";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const provided = req.headers["x-service-token"];
  if (!provided || !serviceToken || provided !== serviceToken) {
    return res.status(401).json({ error: "Missing or invalid X-Service-Token" });
  }

  const post = await generateDailyBlogPost(supabaseAdmin);

  const { error } = await supabaseAdmin.from("blog_posts").upsert(
    {
      slug: post.slug,
      title: post.title,
      excerpt: post.excerpt,
      body: post.body,
      // Both status and published_at are required to be publicly visible —
      // sql/migrations/002_improvements.sql's RLS policy is
      // `status = 'published' and published_at is not null`. status
      // defaults to 'draft', so omitting this silently published nothing
      // (the row existed but no anon reader could ever see it) — the same
      // gap generate-newsletter.ts hit and fixed earlier this session.
      status: "published",
      published_at: new Date().toISOString(),
    },
    { onConflict: "slug" }
  );

  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true, slug: post.slug, title: post.title });
}
