import { notFound } from "next/navigation";
import { marked } from "marked";
import { supabase } from "@/lib/supabaseClient";

export const revalidate = 3600;

type Post = { slug: string; title: string; body_markdown: string; published_at: string };

export default async function BlogPostPage({ params }: { params: Promise<{ slug: string }> }) {
  // Next.js 15+ made route params a Promise (was a plain object pre-15) —
  // must await before use. See src/app/dashboard/scans/[id]/page.tsx for
  // the client-component equivalent (useParams() from next/navigation,
  // which is unaffected — this change only applies to Server Component
  // page/layout props).
  const { slug } = await params;

  // Same defensive wrapping as src/app/blog/page.tsx — an unreachable
  // Supabase project throws rather than returning a graceful error here.
  let post: Post | null = null;
  try {
    const { data } = await supabase
      .from("blog_posts")
      .select("slug, title, body_markdown, published_at")
      .eq("slug", slug)
      .not("published_at", "is", null)
      .maybeSingle();
    post = data as Post | null;
  } catch (err) {
    throw new Error(
      "Could not reach Supabase — check NEXT_PUBLIC_SUPABASE_URL/NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local " +
        `(${(err as Error).message}).`
    );
  }

  if (!post) notFound();

  // Safe to render as HTML: body_markdown is only ever written server-side
  // by generate-newsletter using the service role key (see
  // sql/migrations/001_init.sql — no end-user write policy exists on this
  // table), never from user input, so there's no stored-XSS path here.
  const html = marked.parse(post.body_markdown, { async: false }) as string;

  return (
    <article className="mx-auto max-w-3xl px-6 py-16">
      <p className="mb-2 text-xs text-slatedark/60">
        {new Date(post.published_at).toLocaleDateString()}
      </p>
      <h1 className="mb-8 text-3xl font-bold text-atlantic">{post.title}</h1>
      <div
        className="prose prose-slate max-w-none prose-headings:text-atlantic prose-a:text-atlantic"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </article>
  );
}
