// Homepage-only, illustrative recreation of the real dashboard — not a live
// iframe of the authenticated app (can't embed real customer data, and the
// dashboard requires a session), but built from the exact same visual
// language and layout as the real FleetOverview.tsx/ComplianceTrend.tsx/
// ScoreTrend.tsx components rather than an invented mockup. Explicitly
// labelled illustrative, matching this same page's existing testimonials
// disclaimer convention ("Sample quotes from early engagements") — the
// standing rule this whole codebase's docs follow (never claim what isn't
// true) applies to marketing content too.
//
// Two device frames (desktop + mobile) built with plain CSS, not an image
// asset or a screenshot library — matches ScoreTrend.tsx's own precedent of
// hand-rolling visuals rather than reaching for a dependency.

const SAMPLE_SITES = [
  { site: "shop.example.com", score: 92, findings: 1 },
  { site: "app.example.com", score: 68, findings: 4 },
  { site: "booking.example.com", score: 100, findings: 0 },
];

const SAMPLE_COVERAGE = [
  { label: "Cyber Essentials", pct: 88 },
  { label: "OWASP Top 10", pct: 76 },
  { label: "CIS Controls v8", pct: 82 },
];

function scoreColor(score: number): string {
  if (score >= 80) return "text-neon";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

function DashboardMock({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`flex flex-col gap-3 ${compact ? "text-[9px]" : "text-xs"}`}>
      <div className="flex items-center justify-between">
        <p className="font-mono font-semibold text-cybertext/60 uppercase tracking-wide">// fleet overview</p>
        <span className="rounded-full border border-cyberborder px-2 py-0.5 font-mono text-cybermuted">3 sites</span>
      </div>
      <div className="flex flex-col gap-1.5 rounded-lg border border-cyberborder bg-cyberbg/60 p-2.5">
        {SAMPLE_SITES.map((s) => (
          <div key={s.site} className="flex items-center justify-between gap-2">
            <span className="truncate font-mono text-cybertext/70">{s.site}</span>
            <span className={`font-semibold ${scoreColor(s.score)}`}>{s.score}/100</span>
          </div>
        ))}
      </div>

      <p className="mt-1 font-mono font-semibold text-cybertext/60 uppercase tracking-wide">// compliance coverage</p>
      <div className="flex flex-col gap-1.5 rounded-lg border border-cyberborder bg-cyberbg/60 p-2.5">
        {SAMPLE_COVERAGE.map((c) => (
          <div key={c.label} className="flex items-center gap-2">
            <span className="w-20 shrink-0 truncate text-cybertext/60">{c.label}</span>
            <div className="h-1.5 flex-1 rounded-full bg-cyberborder/40">
              <div className="h-1.5 rounded-full bg-neon" style={{ width: `${c.pct}%` }} />
            </div>
            <span className="w-7 shrink-0 text-right font-mono text-cybertext/50">{c.pct}%</span>
          </div>
        ))}
      </div>

      <div className="mt-1 flex items-center gap-2 rounded-lg border border-neon/30 bg-neon/5 p-2.5">
        <span className="text-neon">✓</span>
        <span className="text-cybertext/70">PR opened: bump lodash 4.17.15 → 4.17.21</span>
      </div>
    </div>
  );
}

function DesktopFrame() {
  return (
    <div className="w-full max-w-md rounded-xl border border-cyberborder bg-cyberpanel shadow-glowsm">
      <div className="flex items-center gap-1.5 border-b border-cyberborder px-3 py-2">
        <span className="h-2 w-2 rounded-full bg-red-400/60" />
        <span className="h-2 w-2 rounded-full bg-amber-400/60" />
        <span className="h-2 w-2 rounded-full bg-neon/60" />
        <span className="ml-2 truncate font-mono text-[9px] text-cybermuted">hebridescyber.co.uk/dashboard</span>
      </div>
      <div className="p-4">
        <DashboardMock />
      </div>
    </div>
  );
}

function MobileFrame() {
  return (
    <div className="w-40 shrink-0 rounded-[1.5rem] border-4 border-cyberborder bg-cyberpanel p-1 shadow-glowsm sm:w-44">
      <div className="rounded-[1rem] border border-cyberborder/60 bg-cyberpanel p-2.5">
        <div className="mx-auto mb-2 h-1 w-8 rounded-full bg-cyberborder/60" />
        <DashboardMock compact />
      </div>
    </div>
  );
}

export default function ProductPreview() {
  return (
    <div>
      <div className="flex flex-wrap items-end justify-center gap-6 sm:gap-10">
        <DesktopFrame />
        <MobileFrame />
      </div>
      <p className="mx-auto mt-6 max-w-md text-center text-xs text-cybermuted">
        Illustrative preview with sample data — see the real thing with your
        own site on a free scan.
      </p>
    </div>
  );
}
