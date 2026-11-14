// Publishes due scheduled blog posts. Run by
// .github/workflows/publish-scheduled-posts.yml; the logic is in
// src/lib/blogSchedule.ts (publishDuePosts).
//
// Run with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npm run blog:publish-scheduled

import { createScriptSupabase } from "../lib/scriptSupabase";
import { publishDuePosts } from "../lib/blogSchedule";

async function main() {
  const supabaseAdmin = createScriptSupabase();

  const outcome = await publishDuePosts(supabaseAdmin);
  switch (outcome.status) {
    case "nothing_due":
      console.log("No scheduled posts are due.");
      return;
    case "published":
      console.log(`Published ${outcome.slugs.length} scheduled post(s): ${outcome.slugs.join(", ")}`);
      return;
    case "error":
      console.error(`Could not publish due posts: ${outcome.error}`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("publish-scheduled-posts failed:", err);
  process.exit(1);
});
