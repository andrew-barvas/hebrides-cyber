// Azure Function (HTTP trigger): generate-newsletter
//
// Drafts and publishes the weekly blog post (see src/lib/newsletter.ts),
// triggered by .github/workflows/weekly-newsletter.yml on a cron. Gated
// behind X-Service-Token (same shared secret as run-scan's scheduled
// calls) since this writes public-facing content — it should not be
// callable by just anyone who finds the URL.

import { createClient } from "@supabase/supabase-js";
import { generateNewsletterPost } from "../../lib/newsletter";

type HttpRequest = { headers: Record<string, string | undefined> };
type HttpResponseInit = { status: number; jsonBody: unknown };

const supabaseAdmin = createClient(process.env.SUPABASE_URL ?? "", process.env.SUPABASE_SERVICE_ROLE_KEY ?? "");
const serviceToken = process.env.GITHUB_ACTIONS_TOKEN ?? "";

export default async function generateNewsletter(req: HttpRequest): Promise<HttpResponseInit> {
  const provided = req.headers["x-service-token"];
  if (!provided || !serviceToken || provided !== serviceToken) {
    return { status: 401, jsonBody: { error: "Missing or invalid X-Service-Token" } };
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

  if (error) {
    return { status: 500, jsonBody: { error: error.message } };
  }

  return { status: 200, jsonBody: { ok: true, slug: post.slug, title: post.title } };
}
