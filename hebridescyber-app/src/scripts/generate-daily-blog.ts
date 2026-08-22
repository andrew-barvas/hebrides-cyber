// Generates and publishes the daily cyber security blog post
// (src/lib/newsletter.ts's generateDailyBlogPost) directly against Supabase,
// run by .github/workflows/daily-blog.yml as a plain script — not, as it
// used to be, a curl POST to a Next.js API route on Azure Static Web Apps.
//
// That HTTP round-trip was the bug: a real production run
// (github.com/andrew-barvas/hebrides-cyber/actions/runs/32561015093) came
// back "Backend call failure" after 46s — Azure SWA's own proxy error text
// for when its Free-tier managed Functions layer kills a request, the exact
// signature already diagnosed once this session for run-scan.ts (see that
// file's header) and fixed there by moving off synchronous HTTP execution
// entirely. The external fetches this route makes (KEV/NVD/RSS) measured
// well under a second locally, so the likely culprits are cold start plus
// collectRecentScanStats's unbounded scan_results query, both of which
// disappear once nothing has to survive Azure's request/response cycle at
// all — this script talks to Supabase directly, the same way
// run-queued-scan-jobs.ts does for the exact same reason.
//
// src/pages/api/generate-daily-blog.ts (and its weekly sibling,
// generate-newsletter.ts) are deleted, not just superseded — nothing else
// in the app called them, and an HTTP entry point that's known to hit this
// ceiling isn't worth keeping around as a trap for the next person to
// accidentally invoke.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/generate-daily-blog.ts

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { generateDailyBlogPost } from "../lib/newsletter";

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
      // gap the original API route already fixed once, kept here.
      status: "published",
      published_at: new Date().toISOString(),
    },
    { onConflict: "slug" }
  );

  if (error) {
    console.error(`Failed to publish daily blog post "${post.slug}":`, error.message);
    process.exit(1);
  }

  console.log(`Published daily blog post: ${post.slug} — "${post.title}"`);
}

main().catch((err) => {
  console.error("generate-daily-blog failed:", err);
  process.exit(1);
});
