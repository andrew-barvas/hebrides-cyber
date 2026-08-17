// POST /api/generate-newsletter — drafts and publishes the weekly blog post
// (see src/lib/newsletter.ts), triggered by
// .github/workflows/weekly-newsletter.yml on a cron. Gated behind
// X-Service-Token (same shared secret as the scheduled-scans queue) since
// this writes public-facing content — it should not be callable by just
// anyone who finds the URL.
//
// Rebuilt as a Next.js API route alongside run-scan — see that file's header
// for why (the standalone src/functions/ Azure Functions app was never
// actually deployable).
import type { NextApiRequest, NextApiResponse } from "next";
import { generateNewsletterPost } from "@/lib/newsletter";
import { supabaseAdmin } from "@/lib/apiAuth";

const serviceToken = process.env.GITHUB_ACTIONS_TOKEN ?? "";

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
      body_markdown: post.body_markdown,
      published_at: new Date().toISOString(),
    },
    { onConflict: "slug" }
  );

  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true, slug: post.slug, title: post.title });
}
