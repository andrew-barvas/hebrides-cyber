// /profile/<slug> — a customer's published security profile for one site
// (src/lib/securityProfile.ts, migration 073). Rendered on the server with the
// service role; only the grade, score, date and passing practices are shown,
// never open findings. Kept out of search engines: it's the customer's to
// share, not ours to index.
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { ratingFor } from "@/lib/executiveReport";
import { buildPublicProfile, loadLatestScanForProfile, loadProfileBySlug, STALE_AFTER_DAYS } from "@/lib/securityProfile";

export const metadata: Metadata = {
  title: "Security profile — Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default async function ProfilePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const row = await loadProfileBySlug(supabaseAdmin, slug);
  if (!row) notFound();
  const profile = buildPublicProfile({ host: row.target_host, scan: await loadLatestScanForProfile(supabaseAdmin, row) });
  const rating = ratingFor(profile.score);
  const current = !profile.stale && profile.score !== null;

  return (
    <div className="mx-auto max-w-2xl px-4 py-12">
      <p className="font-mono text-xs uppercase tracking-widest text-cybermuted">Security profile</p>
      <h1 className="mt-2 break-all text-3xl font-bold">{profile.host}</h1>

      {current ? (
        <div className="mt-6 rounded-xl border border-cyberborder bg-cyberpanel p-6">
          <p className="text-sm text-cybermuted">Last checked {new Date(profile.checkedAt!).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}</p>
          <p className="mt-2 text-4xl font-bold" style={{ color: rating.colour }}>
            {rating.label}
          </p>
          <p className="mt-1 text-cybertext/80">Security score {profile.score}/100</p>
        </div>
      ) : (
        <div className="mt-6 rounded-xl border border-cyberborder bg-cyberpanel p-6">
          <p className="text-cybertext/80">This site hasn&apos;t been checked in the last {STALE_AFTER_DAYS} days, so there&apos;s no current result to show.</p>
        </div>
      )}

      {current && profile.passes.length > 0 && (
        <section className="mt-8" aria-labelledby="passes-heading">
          <h2 id="passes-heading" className="text-lg font-semibold">
            Good practices in place
          </h2>
          <ul className="mt-3 space-y-2">
            {profile.passes.map((p) => (
              <li key={p.key} className="flex gap-2 text-cybertext/90">
                <span aria-hidden="true" className="text-neon">
                  ✓
                </span>
                {p.label}
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="mt-10 text-sm text-cybermuted">
        The owner of this site chose to publish this profile. It reflects automated, outside-in checks by{" "}
        <Link href="/" className="font-semibold text-neon underline-offset-2 hover:underline">
          Hebrides Cyber
        </Link>{" "}
        and is not a certification or a penetration test.{" "}
        <Link href="/check" className="font-semibold text-neon underline-offset-2 hover:underline">
          Check your own site free
        </Link>
        .
      </p>
    </div>
  );
}
