import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";

// Server component — fetches published posts at request time. Public data
// (RLS policy "Anyone can read published posts" in
// sql/migrations/001_init.sql), so the anon client is fine here, no auth
// needed.
export const revalidate = 3600; // re-fetch at most once an hour

type PostSummary = { slug: string; title: string; excerpt: string; published_at: string };

export default async function BlogIndexPage() {
  // Wrapped in try/catch deliberately: if NEXT_PUBLIC_SUPABASE_URL isn't a
  // real, reachable project yet (e.g. still the placeholder from
  // src/lib/supabaseClient.ts, or the project is paused), the underlying
  // fetch throws rather than returning a graceful { error } — an unhandled
  // throw here would crash the whole page instead of just this section.
  let posts: PostSummary[] | null = null;
  let error: string | null = null;
  try {
    const { data, error: queryError } = await supabase
      .from("blog_posts")
      .select("slug, title, excerpt, published_at")
      .not("published_at", "is", null)
      .order("published_at", { ascending: false });
    posts = data;
    error = queryError?.message ?? null;
  } catch (err) {
    error =
      "Could not reach Supabase — check NEXT_PUBLIC_SUPABASE_URL/NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local " +
      `(${(err as Error).message}).`;
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="mb-2 text-3xl font-bold text-atlantic">Security Weekly</h1>
      <p className="mb-10 text-slatedark/80">
        A weekly cybersecurity newsletter for small businesses, grounded in
        real (anonymised) data from Hebrides Cyber Security Score scans —
        see <code>src/lib/newsletter.ts</code> for how it's generated.
      </p>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {!error && (posts ?? []).length === 0 && (
        <p className="text-sm text-slatedark/60">
          No posts yet — the first one publishes via the weekly-newsletter.yml
          workflow. Trigger it manually (workflow_dispatch) to seed one.
        </p>
      )}

      <div className="space-y-8">
        {posts?.map((post) => (
          <Link key={post.slug} href={`/blog/${post.slug}`} className="block rounded-lg border border-slate-200 p-6 hover:border-atlantic">
            <p className="mb-1 text-xs text-slatedark/60">
              {new Date(post.published_at).toLocaleDateString()}
            </p>
            <h2 className="text-xl font-semibold text-atlantic">{post.title}</h2>
            <p className="mt-2 text-sm text-slatedark/80">{post.excerpt}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
