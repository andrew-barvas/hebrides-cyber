// Generates and publishes the weekly cyber security newsletter
// (src/lib/newsletter.ts's generateWeeklyNewsletterPost) directly against
// Supabase, run by .github/workflows/weekly-newsletter.yml as a plain
// script. See src/scripts/generate-daily-blog.ts's header for why this
// moved off a curl POST to an Azure-hosted API route — same real production
// failure mode, same fix, applied to both posts since they share the exact
// same shape of risk (external fetches + an unbounded scan_results query,
// both now running in a GitHub Actions runner instead of behind Azure SWA's
// Free-tier Functions proxy).
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/generate-weekly-newsletter.ts

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { generateWeeklyNewsletterPost } from "../lib/newsletter";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const post = await generateWeeklyNewsletterPost(supabaseAdmin);

  const { error } = await supabaseAdmin.from("blog_posts").upsert(
    {
      slug: post.slug,
      title: post.title,
      excerpt: post.excerpt,
      body: post.body,
      // See generate-daily-blog.ts's identical comment — both status and
      // published_at are required for sql/migrations/002_improvements.sql's
      // RLS policy to let anyone actually see the post.
      status: "published",
      published_at: new Date().toISOString(),
    },
    { onConflict: "slug" }
  );

  if (error) {
    console.error(`Failed to publish weekly newsletter "${post.slug}":`, error.message);
    process.exit(1);
  }

  console.log(`Published weekly newsletter: ${post.slug} — "${post.title}"`);
}

main().catch((err) => {
  console.error("generate-weekly-newsletter failed:", err);
  process.exit(1);
});
