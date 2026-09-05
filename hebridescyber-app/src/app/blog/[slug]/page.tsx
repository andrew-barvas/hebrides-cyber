import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { marked } from "marked";
import DOMPurify from "isomorphic-dompurify";
import { supabase } from "@/lib/supabaseClient";

export const revalidate = 3600;
export const dynamicParams = true;

export async function generateStaticParams() {
  try {
    const { data } = await supabase
      .from("blog_posts")
      .select("slug")
      .eq("status", "published");
    return (data ?? []).map(({ slug }) => ({ slug }));
  } catch {
    return [];
  }
}

type Post = {
  slug: string;
  title: string;
  body: string;
  excerpt: string;
  published_at: string;
  cover_image_url: string | null;
  tags: string[];
  meta_description: string | null;
  og_image: string | null;
};

type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  let post: Post | null = null;
  try {
    const { data } = await supabase
      .from("blog_posts")
      .select("title, excerpt, og_image, meta_description")
      .eq("slug", slug)
      .eq("status", "published")
      .maybeSingle();
    post = data as Post | null;
  } catch { /* notFound() handles this below */ }

  if (!post) return { title: "Post not found — Hebrides Cyber" };

  const description = post.meta_description ?? post.excerpt;
  return {
    title: `${post.title} — Hebrides Cyber`,
    description,
    openGraph: {
      title: post.title,
      description,
      images: post.og_image ? [{ url: post.og_image }] : [],
      type: "article",
    },
    twitter: {
      card: post.og_image ? "summary_large_image" : "summary",
      title: post.title,
      description,
      images: post.og_image ? [post.og_image] : [],
    },
  };
}

function readingTime(text: string): number {
  const words = text.trim().split(/\s+/).length;
  return Math.max(1, Math.round(words / 200));
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params;

  let post: Post | null = null;
  try {
    const { data } = await supabase
      .from("blog_posts")
      .select("slug, title, body, excerpt, published_at, cover_image_url, tags, meta_description, og_image")
      .eq("slug", slug)
      .eq("status", "published")
      .maybeSingle();
    post = data as Post | null;
  } catch (err) {
    throw new Error(
      `Could not reach Supabase — check NEXT_PUBLIC_SUPABASE_URL in .env.local (${(err as Error).message}).`
    );
  }

  if (!post) notFound();

  // post.body's markdown embeds real external text (NVD CVE descriptions,
  // RSS article titles, CISA KEV entries — src/lib/newsletter.ts) that
  // Hebrides Cyber doesn't author or control. A CVE description routinely
  // contains a literal <script>/onerror snippet as part of describing the
  // vulnerability it's about — marked.parse() doesn't sanitize its output,
  // so without this, that snippet would render verbatim on a public,
  // unauthenticated page. Sanitizing here (not just escaping at generation
  // time — see newsletter.ts's own escaping) also covers admin-authored
  // posts and the AI-narrative path, neither of which this render step
  // should have to trust.
  const html = DOMPurify.sanitize(marked.parse(post.body, { async: false }) as string);
  const mins = readingTime(post.body);

  return (
    <div className="bg-slatelight dark:bg-cyberbg min-h-screen">
      {/* Hero strip */}
      <div className="relative overflow-hidden bg-slatelight dark:bg-cyberbg px-6 pt-14 pb-10">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-0 dark:opacity-50" />
        <div className="relative mx-auto max-w-3xl">
          <Link
            href="/blog"
            className="mb-6 inline-flex items-center gap-1.5 font-mono text-xs text-slatedark/70 hover:text-atlantic dark:text-cybertext/60 dark:hover:text-neon transition-colors"
          >
            ← back to Security Weekly
          </Link>

          {/* Tags */}
          {(post.tags ?? []).length > 0 && (
            <div className="mb-4 flex flex-wrap gap-2">
              {post.tags.map((tag) => (
                <Link
                  key={tag}
                  href={`/blog?tag=${encodeURIComponent(tag)}`}
                  className="rounded-full border border-slate-200 dark:border-cyberborder px-3 py-0.5 font-mono text-[10px] text-slatedark/60 hover:border-atlantic hover:text-atlantic dark:text-neon/70 dark:hover:border-neon dark:hover:text-neon transition-colors"
                >
                  {tag}
                </Link>
              ))}
            </div>
          )}

          <h1 className="text-3xl font-bold leading-tight text-slatedark dark:text-cybertext sm:text-4xl">
            {post.title}
          </h1>

          <div className="mt-4 flex flex-wrap items-center gap-3 font-mono text-xs text-slatedark/70 dark:text-cybertext/60">
            <span>
              {new Date(post.published_at).toLocaleDateString("en-GB", {
                day: "numeric",
                month: "long",
                year: "numeric",
              })}
            </span>
            <span className="text-slatedark/30 dark:text-cybertext/20">·</span>
            <span>{mins} min read</span>
          </div>

          {post.excerpt && (
            <p className="mt-5 text-base leading-relaxed text-slatedark/70 dark:text-cybertext/60">
              {post.excerpt}
            </p>
          )}
        </div>
      </div>

      {/* Cover image */}
      {post.cover_image_url && (
        <div className="mx-auto max-w-3xl px-6 pb-6">
          <img
            src={post.cover_image_url}
            alt={post.title}
            className="w-full rounded-xl object-cover max-h-72 border border-slate-200 dark:border-cyberborder"
          />
        </div>
      )}

      {/* Body */}
      <div className="mx-auto max-w-3xl px-6 pb-20">
        <div
          className={[
            "prose prose-slate max-w-none",
            // Dark mode prose overrides
            "dark:prose-invert",
            "prose-headings:text-atlantic dark:prose-headings:text-neon",
            "prose-a:text-atlantic dark:prose-a:text-neon prose-a:no-underline hover:prose-a:underline",
            "prose-strong:text-slatedark dark:prose-strong:text-cybertext",
            "prose-code:rounded prose-code:px-1.5 prose-code:py-0.5 prose-code:text-sm",
            "prose-code:bg-slate-100 prose-code:text-atlantic dark:prose-code:bg-cyberpanel dark:prose-code:text-neon",
            "prose-pre:bg-slate-100 prose-pre:border prose-pre:border-slate-200",
            "dark:prose-pre:bg-cyberpanel dark:prose-pre:border-cyberborder",
            "prose-blockquote:border-l-atlantic dark:prose-blockquote:border-l-neon",
            "prose-blockquote:text-slatedark/70 dark:prose-blockquote:text-cybertext/60",
            "prose-hr:border-slate-200 dark:prose-hr:border-cyberborder",
            "prose-th:text-slatedark dark:prose-th:text-cybertext",
            "prose-td:text-slatedark/80 dark:prose-td:text-cybertext/70",
          ].join(" ")}
          dangerouslySetInnerHTML={{ __html: html }}
        />

        {/* Footer tags */}
        {(post.tags ?? []).length > 0 && (
          <div className="mt-12 flex flex-wrap gap-2 border-t border-slate-200 dark:border-cyberborder pt-6">
            {post.tags.map((tag) => (
              <Link
                key={tag}
                href={`/blog?tag=${encodeURIComponent(tag)}`}
                className="rounded-full border border-slate-200 dark:border-cyberborder px-3 py-1 font-mono text-xs text-slatedark/60 hover:border-atlantic hover:text-atlantic dark:text-cybertext/50 dark:hover:border-neon dark:hover:text-neon transition-colors"
              >
                {tag}
              </Link>
            ))}
          </div>
        )}

        {/* CTA */}
        <div className="mt-10 rounded-xl border border-slate-200 dark:border-cyberborder bg-white dark:bg-cyberpanel p-6">
          <p className="font-mono text-xs text-slatedark/50 dark:text-cybertext/40 mb-1">
            <span className="text-slatedark/30 dark:text-cybertext/20">$</span> ./get-your-score
          </p>
          <p className="text-sm font-semibold text-slatedark dark:text-cybertext">
            Get a free Security Score for your site
          </p>
          <p className="mt-1 text-xs text-slatedark/60 dark:text-cybertext/50">
            Automated TLS, headers, DNS, and exposure checks — results in under a minute.
          </p>
          <Link
            href="/contact"
            className="mt-4 inline-block rounded-md bg-atlantic dark:bg-neon px-4 py-2 text-sm font-semibold text-white dark:text-cyberbg hover:opacity-90 transition-opacity"
          >
            Request a free scan
          </Link>
        </div>
      </div>
    </div>
  );
}
