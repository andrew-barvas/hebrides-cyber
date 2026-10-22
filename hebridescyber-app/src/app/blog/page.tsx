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
      .order("published_at", { ascending: false })
      // Bounded: the index renders every card, so an unbounded select grows with the archive.
      .limit(100);

    if (tag) {
      query = query.contains("tags", [tag]);
    }

    const { data, error: queryError } = await query;
    posts = (data ?? []) as PostSummary[];
    error = queryError?.message ?? null;
  } catch (err) {
    error = `Could not reach Supabase — check NEXT_PUBLIC_SUPABASE_URL in .env.local (${(err as Error).message}).`;
  }

  const allTags = [...new Set(posts.flatMap((p) => p.tags ?? []))].sort();

  return (
    <div className="bg-cyberbg min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> cat security-weekly.log
          </p>
          <h1 className="text-4xl font-bold text-cybertext">Security Weekly</h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Cybersecurity insights for small businesses and SaaS teams — grounded in
            real (anonymised) data from Hebrides Cyber scans.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-3xl px-6 pb-20">
        <div className="flex justify-end pt-6">
          <a href="/feed.xml" className="font-mono text-xs text-cybertext/60 hover:text-neon" aria-label="RSS feed for Security Weekly">
            RSS feed
          </a>
        </div>

        {/* Tag filter pills */}
        {allTags.length > 0 && (
          <div className="mb-8 flex flex-wrap gap-2 pt-10">
            <Link
              href="/blog"
              className={`rounded-full px-3 py-1 text-xs font-mono border transition-colors ${
                !tag
                  ? "bg-neon text-cyberbg border-neon"
                  : "border-cyberborder text-cybertext/60 hover:border-neon hover:text-neon"
              }`}
            >
              All
            </Link>
            {allTags.map((t) => (
              <Link
                key={t}
                href={`/blog?tag=${encodeURIComponent(t)}`}
                className={`rounded-full px-3 py-1 text-xs font-mono border transition-colors ${
                  tag === t
                    ? "bg-neon text-cyberbg border-neon"
                    : "border-cyberborder text-cybertext/60 hover:border-neon hover:text-neon"
                }`}
              >
                {t}
              </Link>
            ))}
          </div>
        )}

        {!allTags.length && <div className="pt-10" />}

        {error && <p className="mb-6 text-sm text-red-400">{error}</p>}

        {!error && posts.length === 0 && (
          <p className="font-mono text-sm text-cybertext/50">
            {tag ? `No posts tagged "${tag}" yet.` : "// no posts yet — trigger the daily-blog or weekly-newsletter workflow to seed one."}
          </p>
        )}

        <div className="space-y-4">
          {posts.map((post) => (
            <Link
              key={post.slug}
              href={`/blog/${post.slug}`}
              className="group flex gap-5 rounded-xl border border-cyberborder bg-cyberpanel p-5 hover:border-neon transition-colors"
            >
              {post.cover_image_url && (
                <img
                  src={post.cover_image_url}
                  alt={post.title}
                  width={112}
                  height={80}
                  loading="lazy"
                  decoding="async"
                  className="h-20 w-28 shrink-0 rounded-lg object-cover"
                />
              )}
              <div className="min-w-0">
                <p className="mb-1 font-mono text-xs text-cybertext/60">
                  {new Date(post.published_at).toLocaleDateString("en-GB", {
                    day: "numeric",
                    month: "long",
                    year: "numeric",
                  })}
                </p>
                <h2 className="text-lg font-semibold text-cybertext group-hover:text-neon transition-colors">
                  {post.title}
                </h2>
                <p className="mt-1 text-sm text-cybertext/60 line-clamp-2">{post.excerpt}</p>
                {(post.tags ?? []).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {post.tags.slice(0, 4).map((t) => (
                      <span
                        key={t}
                        className="rounded border border-cyberborder px-1.5 py-0.5 font-mono text-[10px] text-neon/70"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
