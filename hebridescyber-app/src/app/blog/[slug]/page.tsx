import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { marked } from "marked";
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
  } catch { /* silent — notFound() handles missing post below */ }

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

  const html = marked.parse(post.body, { async: false }) as string;
  const mins = readingTime(post.body);

  return (
    <article className="mx-auto max-w-3xl px-6 py-16">
      {/* Cover image */}
      {post.cover_image_url && (
        <img
          src={post.cover_image_url}
          alt={post.title}
          className="mb-8 w-full rounded-xl object-cover max-h-72"
        />
      )}

      {/* Meta row */}
      <div className="mb-4 flex flex-wrap items-center gap-3 text-xs text-slatedark/50">
        <span>{new Date(post.published_at).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}</span>
        <span>·</span>
        <span>{mins} min read</span>
        {(post.tags ?? []).map((tag) => (
          <a
            key={tag}
            href={`/blog?tag=${encodeURIComponent(tag)}`}
            className="rounded bg-slate-100 px-2 py-0.5 hover:bg-atlantic/10 hover:text-atlantic"
          >
            {tag}
          </a>
        ))}
      </div>

      <h1 className="mb-8 text-3xl font-bold text-atlantic leading-tight">{post.title}</h1>

      {/* Body */}
      <div
        className="prose prose-slate max-w-none prose-headings:text-atlantic prose-a:text-atlantic prose-code:bg-slate-100 prose-code:px-1 prose-code:rounded"
        dangerouslySetInnerHTML={{ __html: html }}
      />

      {/* Tags footer */}
      {(post.tags ?? []).length > 0 && (
        <div className="mt-12 flex flex-wrap gap-2 border-t border-slate-100 pt-6">
          {post.tags.map((tag) => (
            <a
              key={tag}
              href={`/blog?tag=${encodeURIComponent(tag)}`}
              className="rounded-full border border-slate-200 px-3 py-1 text-xs text-slatedark/70 hover:border-atlantic hover:text-atlantic"
            >
              {tag}
            </a>
          ))}
        </div>
      )}
    </article>
  );
}
