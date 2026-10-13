// Scheduled/future-dated blog publishing. A post saved with
// status: "scheduled" and a future published_at is excluded from every
// public read (blog/page.tsx, blog/[slug]/page.tsx, sitemap.ts,
// feed.xml/route.ts, and the RLS policy itself all filter on
// status = 'published' by exact match — see migration 054) until
// src/scripts/publish-scheduled-posts.ts flips it to 'published'.
//
// isPostDue is pure/unit-testable, fed a `now` by the caller — same model
// as scanCadence.ts's isScanDue(): the script does the Supabase query and
// passes real rows through this to decide which are actually due, rather
// than trusting a database-side date comparison it can't unit-test as easily.

import type { SupabaseClient } from "@supabase/supabase-js";

/** Whether a scheduled post's publish time has arrived. */
export function isPostDue(publishedAt: string, now: Date): boolean {
  const t = Date.parse(publishedAt);
  if (!Number.isFinite(t)) return false; // an unparseable date is never "due" — never guess
  return t <= now.getTime();
}

export type PublishDueResult =
  | { status: "nothing_due" }
  | { status: "published"; slugs: string[] }
  | { status: "error"; error: string };

type ScheduledRow = { slug: string; published_at: string | null };

/**
 * Finds every status:"scheduled" post whose published_at has arrived and
 * flips it to "published" — published_at is left exactly as the admin set
 * it, so the post's displayed date stays accurate. Never touches a row
 * whose published_at is unparseable or still in the future.
 */
export async function publishDuePosts(supabase: SupabaseClient, now: Date = new Date()): Promise<PublishDueResult> {
  const { data, error } = await supabase.from("blog_posts").select("slug, published_at").eq("status", "scheduled");
  if (error) return { status: "error", error: error.message };

  const due = ((data as ScheduledRow[]) ?? []).filter((row) => row.published_at && isPostDue(row.published_at, now));
  if (due.length === 0) return { status: "nothing_due" };

  const published: string[] = [];
  for (const row of due) {
    const { error: updateError } = await supabase.from("blog_posts").update({ status: "published" }).eq("slug", row.slug);
    if (updateError) return { status: "error", error: `${row.slug}: ${updateError.message}` };
    published.push(row.slug);
  }
  return { status: "published", slugs: published };
}
