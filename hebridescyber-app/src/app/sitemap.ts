import type { MetadataRoute } from "next";
import { supabase } from "@/lib/supabaseClient";

// No sitemap existed before this — a real gap for a marketing site trying
// to rank. Static marketing pages + every published blog post (blog/page.tsx
// already queries blog_posts the same way, server-side, with the same
// status/published_at filter — kept in sync with that query rather than a
// looser one, so the sitemap never lists a post that 404s).
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

const STATIC_PAGES: Array<{ path: string; changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"]; priority: number }> = [
  { path: "", changeFrequency: "weekly", priority: 1.0 },
  { path: "/pricing", changeFrequency: "monthly", priority: 0.9 },
  { path: "/what-we-check", changeFrequency: "monthly", priority: 0.8 },
  { path: "/check", changeFrequency: "monthly", priority: 0.8 },
  { path: "/web-check-alternative", changeFrequency: "monthly", priority: 0.8 },
  { path: "/cyber-essentials", changeFrequency: "monthly", priority: 0.8 },
  { path: "/ai-threats", changeFrequency: "monthly", priority: 0.6 },
  { path: "/sample-reports", changeFrequency: "monthly", priority: 0.6 },
  { path: "/sbom", changeFrequency: "monthly", priority: 0.5 },
  { path: "/services", changeFrequency: "monthly", priority: 0.7 },
  { path: "/blog", changeFrequency: "daily", priority: 0.7 },
  { path: "/agencies", changeFrequency: "monthly", priority: 0.6 },
  { path: "/docs/ci", changeFrequency: "monthly", priority: 0.5 },
  { path: "/tourism", changeFrequency: "monthly", priority: 0.6 },
  { path: "/churches", changeFrequency: "monthly", priority: 0.6 },
  { path: "/local-trades", changeFrequency: "monthly", priority: 0.6 },
  { path: "/contact", changeFrequency: "yearly", priority: 0.5 },
  { path: "/privacy", changeFrequency: "yearly", priority: 0.2 },
  { path: "/terms", changeFrequency: "yearly", priority: 0.2 },
];

export const revalidate = 3600;

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticEntries: MetadataRoute.Sitemap = STATIC_PAGES.map((p) => ({
    url: `${SITE_URL}${p.path}`,
    changeFrequency: p.changeFrequency,
    priority: p.priority,
  }));

  const { data: posts } = await supabase
    .from("blog_posts")
    .select("slug, published_at")
    .eq("status", "published")
    .not("published_at", "is", null)
    .order("published_at", { ascending: false });

  const postEntries: MetadataRoute.Sitemap = (posts ?? []).map((post) => ({
    url: `${SITE_URL}/blog/${post.slug}`,
    lastModified: post.published_at ?? undefined,
    changeFrequency: "yearly",
    priority: 0.5,
  }));

  return [...staticEntries, ...postEntries];
}
