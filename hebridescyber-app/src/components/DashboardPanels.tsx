"use client";

import type { ViewFinding } from "@/components/ScanReportView";
import type { DetectedTech } from "@/lib/scanners/fingerprint";

type WafStatus = {
  status: "completed";
  waf: string | null;
  vendor: string | null;
  confidence: number;
} | { status: "not_configured" | "error" };

type CmsMapStatus = {
  status: "completed";
  cmsType: string;
  findings: Array<{ type: string; detail: string }>;
} | { status: "not_configured" | "not_applicable" | "error" };

type PhotonStatus = {
  status: "completed";
  assets: Array<{ type: string; value: string }>;
} | { status: "not_configured" | "error" };

type GospiderStatus = {
  status: "completed";
  endpoints: Array<{ type: string; value: string; source: string }>;
} | { status: "not_configured" | "error" };

type ExtendedResults = {
  whatwaf?: WafStatus;
  cmsmap?: CmsMapStatus;
  wpscan?: { status: string; findings?: Array<{ type: string }> };
  photon?: PhotonStatus;
  gospider?: GospiderStatus;
  zapAjaxSpider?: { status: string; urls?: string[] };
  [key: string]: unknown;
};

type ScanResults = {
  fingerprint?: {
    status?: string;
    technologies?: DetectedTech[];
  };
  extended?: ExtendedResults;
  findings?: ViewFinding[];
};

export function WafIndicator({ results }: { results: ScanResults }) {
  const waf = results.extended?.whatwaf;
  if (!waf || waf.status !== "completed") return null;

  const w = waf as Extract<WafStatus, { status: "completed" }>;
  const detected = w.waf !== null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-cybertext/40">WAF protection</p>
      <div className="flex items-center gap-3">
        <span className={`text-2xl font-bold ${detected ? "text-neon" : "text-red-400"}`}>
          {detected ? "✓" : "✗"}
        </span>
        <div>
          <p className="text-sm font-medium text-cybertext">
            {detected ? w.waf : "No WAF detected"}
          </p>
          {detected && w.vendor && (
            <p className="text-xs text-cybertext/50">{w.vendor}</p>
          )}
          {detected && (
            <p className="text-xs text-cybertext/40">Confidence: {Math.round(w.confidence)}%</p>
          )}
        </div>
      </div>
    </div>
  );
}

export function CmsStatusPanel({ results }: { results: ScanResults }) {
  const cmsmap = results.extended?.cmsmap;
  const wpscan = results.extended?.wpscan;

  const hasCmsData = cmsmap && cmsmap.status === "completed";
  const hasWpData = wpscan && wpscan.status === "completed";
  if (!hasCmsData && !hasWpData) return null;

  const cms = hasCmsData ? (cmsmap as Extract<CmsMapStatus, { status: "completed" }>) : null;
  const wpFindings = hasWpData
    ? ((wpscan as { findings?: Array<{ type: string }> }).findings ?? [])
    : [];

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-cybertext/40">CMS security</p>
      {cms && (
        <div className="mb-2 flex items-center gap-2">
          <span className="text-sm font-bold text-neon">{cms.cmsType}</span>
          <span className={`rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${
            cms.findings.length > 0
              ? "border-red-400/30 bg-red-400/10 text-red-400"
              : "border-neon/30 bg-neon/10 text-neon"
          }`}>
            {cms.findings.length > 0 ? `${cms.findings.length} issues` : "Clean"}
          </span>
        </div>
      )}
      {wpFindings.length > 0 && (
        <p className="text-xs text-cybertext/50">
          WPScan: {wpFindings.length} finding{wpFindings.length !== 1 ? "s" : ""}
        </p>
      )}
    </div>
  );
}

export function TechStackPanel({ results }: { results: ScanResults }) {
  const techs = results.fingerprint?.technologies;
  if (!techs || techs.length === 0) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-cybertext/40">Detected technologies</p>
      <div className="flex flex-wrap gap-1.5">
        {techs.slice(0, 12).map((tech) => (
          <span
            key={`${tech.name}-${tech.category}`}
            className="rounded-full border border-cyberborder bg-cyberbg/60 px-2 py-0.5 text-[10px] text-cybertext/60"
          >
            {tech.name}{tech.version ? ` ${tech.version}` : ""}
          </span>
        ))}
        {techs.length > 12 && (
          <span className="rounded-full border border-cyberborder bg-cyberbg/60 px-2 py-0.5 text-[10px] text-cybertext/40">
            +{techs.length - 12} more
          </span>
        )}
      </div>
    </div>
  );
}

export function SeverityBreakdown({ findings }: { findings: ViewFinding[] }) {
  const open = findings.filter((f) => f.status !== "fixed");
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of open) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const bars: Array<{ sev: string; count: number; color: string }> = [
    { sev: "Critical", count: counts.critical, color: "bg-red-500" },
    { sev: "High", count: counts.high, color: "bg-orange-500" },
    { sev: "Medium", count: counts.medium, color: "bg-yellow-500" },
    { sev: "Low", count: counts.low, color: "bg-blue-400" },
    { sev: "Info", count: counts.info, color: "bg-cybertext/20" },
  ];
  const max = Math.max(...bars.map((b) => b.count), 1);

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <p className="mb-3 text-[10px] font-semibold uppercase tracking-wide text-cybertext/40">Severity breakdown</p>
      <div className="space-y-1.5">
        {bars.map((b) => (
          <div key={b.sev} className="flex items-center gap-2">
            <span className="w-12 text-right text-[10px] text-cybertext/50">{b.sev}</span>
            <div className="flex-1 h-3 rounded-full bg-cyberbg/50 overflow-hidden">
              <div
                className={`h-full rounded-full ${b.color} transition-all`}
                style={{ width: `${(b.count / max) * 100}%` }}
              />
            </div>
            <span className="w-6 text-right text-xs font-bold text-cybertext/60">{b.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function OsintSummaryPanel({ results }: { results: ScanResults }) {
  const photon = results.extended?.photon;
  const gospider = results.extended?.gospider;
  const ajaxSpider = results.extended?.zapAjaxSpider;

  const hasPhoton = photon && photon.status === "completed" && "assets" in photon;
  const hasGospider = gospider && gospider.status === "completed" && "endpoints" in gospider;
  const hasAjax = ajaxSpider && ajaxSpider.status === "completed" && ajaxSpider.urls;

  if (!hasPhoton && !hasGospider && !hasAjax) return null;

  const photonAssets = hasPhoton ? (photon as Extract<PhotonStatus, { status: "completed" }>).assets : [];
  const gospiderEps = hasGospider ? (gospider as Extract<GospiderStatus, { status: "completed" }>).endpoints : [];
  const ajaxUrls = hasAjax ? (ajaxSpider as { urls: string[] }).urls : [];

  const emailCount = photonAssets.filter((a) => a.type === "email").length;
  const jsEndpointCount =
    photonAssets.filter((a) => a.type === "js-endpoint").length +
    gospiderEps.filter((e) => e.type === "js-endpoint").length;
  const urlCount = photonAssets.filter((a) => a.type === "url").length + gospiderEps.filter((e) => e.type === "url").length;

  const stats = [
    { label: "URLs crawled", count: urlCount },
    { label: "JS endpoints", count: jsEndpointCount },
    { label: "Emails found", count: emailCount },
    { label: "AJAX Spider URLs", count: ajaxUrls.length },
  ].filter((s) => s.count > 0);

  if (stats.length === 0) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-cybertext/40">Attack surface discovery</p>
      <div className="grid grid-cols-2 gap-2">
        {stats.map((s) => (
          <div key={s.label} className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2 text-center">
            <p className="text-lg font-bold text-cybertext">{s.count}</p>
            <p className="text-[10px] text-cybertext/40">{s.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
