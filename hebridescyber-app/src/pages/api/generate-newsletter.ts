// POST /api/generate-newsletter — drafts and publishes the weekly blog post
// (see src/lib/newsletter.ts), triggered by
// .github/workflows/weekly-newsletter.yml on a cron. Gated behind
// X-Service-Token (NEWSLETTER_SERVICE_TOKEN) since this writes public-facing
// content — it should not be callable by just anyone who finds the URL.
// Not named GITHUB_ACTIONS_TOKEN (an earlier name) — GitHub rejects any repo
// secret starting with GITHUB_ as reserved for its own auto-generated ones.
//
// Rebuilt as a Next.js API route alongside run-scan — see that file's header
// for why (the standalone src/functions/ Azure Functions app was never
// actually deployable).
import type { NextApiRequest, NextApiResponse } from "next";
import { generateNewsletterPost } from "@/lib/newsletter";
import { supabaseAdmin } from "@/lib/apiAuth";

const serviceToken = process.env.NEWSLETTER_SERVICE_TOKEN ?? "";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const provided = req.headers["x-service-token"];
  if (!provided || !serviceToken || provided !== serviceToken) {
    return res.status(401).json({ error: "Missing or invalid X-Service-Token" });
  }

  const post = await generateNewsletterPost(supabaseAdmin);

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
      // (the row existed but no anon reader could ever see it).
      status: "published",
      published_at: new Date().toISOString(),
    },
    { onConflict: "slug" }
  );

  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true, slug: post.slug, title: post.title });
}
