import type { Metadata } from "next";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";

export const revalidate = 3600;
export const metadata: Metadata = {
  title: "Security Weekly — Hebrides Cyber",
  description: "Cybersecurity insights for small businesses and SaaS teams, grounded in real scan data.",
};

type PostSummary = {
  slug: string;
  title: string;
  excerpt: string;
  published_at: string;
  tags: string[];
  cover_image_url: string | null;
};

type Props = { searchParams: Promise<{ tag?: string }> };

export default async function BlogIndexPage({ searchParams }: Props) {
  const { tag } = await searchParams;

  let posts: PostSummary[] = [];
  let error: string | null = null;

  try {
    let query = supabase
      .from("blog_posts")
      .select("slug, title, excerpt, published_at, tags, cover_image_url")
      .eq("status", "published")
      .not("published_at", "is", null)
      .order("published_at", { ascending: false });

    // Tag filtering — Supabase array contains operator.
    if (tag) {
      query = query.contains("tags", [tag]);
    }

    const { data, error: queryError } = await query;
    posts = (data ?? []) as PostSummary[];
    error = queryError?.message ?? null;
  } catch (err) {
    error = `Could not reach Supabase — check NEXT_PUBLIC_SUPABASE_URL in .env.local (${(err as Error).message}).`;
  }

  // Collect all unique tags from fetched posts for the filter bar.
  const allTags = [...new Set(posts.flatMap((p) => p.tags ?? []))].sort();

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="mb-2 text-3xl font-bold text-atlantic">Security Weekly</h1>
      <p className="mb-8 text-slatedark/70">
        Cybersecurity insights for small businesses and SaaS teams — grounded in
        real (anonymised) data from Hebrides Cyber scans.
      </p>

      {/* Tag filter pills */}
      {allTags.length > 0 && (
        <div className="mb-8 flex flex-wrap gap-2">
          <Link
            href="/blog"
            className={`rounded-full px-3 py-1 text-xs border ${!tag ? "bg-atlantic text-white border-atlantic" : "border-slate-200 text-slatedark/70 hover:border-atlantic hover:text-atlantic"}`}
          >
            All
          </Link>
          {allTags.map((t) => (
            <Link
              key={t}
              href={`/blog?tag=${encodeURIComponent(t)}`}
              className={`rounded-full px-3 py-1 text-xs border ${tag === t ? "bg-atlantic text-white border-atlantic" : "border-slate-200 text-slatedark/70 hover:border-atlantic hover:text-atlantic"}`}
            >
              {t}
            </Link>
          ))}
        </div>
      )}

      {error && <p className="mb-6 text-sm text-red-600">{error}</p>}

      {!error && posts.length === 0 && (
        <p className="text-sm text-slatedark/60">
          {tag ? `No posts tagged "${tag}" yet.` : "No posts yet — trigger the weekly-newsletter workflow to seed one."}
        </p>
      )}

      <div className="space-y-6">
        {posts.map((post) => (
          <Link
            key={post.slug}
            href={`/blog/${post.slug}`}
            className="group flex gap-5 rounded-xl border border-slate-200 p-5 hover:border-atlantic transition-colors"
          >
            {post.cover_image_url && (
              <img
                src={post.cover_image_url}
                alt={post.title}
                className="h-20 w-28 shrink-0 rounded-lg object-cover"
              />
            )}
            <div className="min-w-0">
              <p className="mb-1 text-xs text-slatedark/50">
                {new Date(post.published_at).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}
              </p>
              <h2 className="text-lg font-semibold text-atlantic group-hover:underline">{post.title}</h2>
              <p className="mt-1 text-sm text-slatedark/70 line-clamp-2">{post.excerpt}</p>
              {(post.tags ?? []).length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {post.tags.slice(0, 4).map((t) => (
                    <span key={t} className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slatedark/60">{t}</span>
                  ))}
                </div>
              )}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
