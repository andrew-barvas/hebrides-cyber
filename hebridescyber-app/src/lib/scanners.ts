// Core security scanner — runs TLS, HTTP headers, DNS, and exposure checks
// against a target URL. No external tools required; uses Node built-ins and
// fetch only. Called from src/pages/api/run-scan.ts.

import * as https from "node:https";
import * as tls from "node:tls";
import { resolveTxt } from "node:dns/promises";

// ── Types ─────────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  severity: Severity;
  title: string;
  detail: string;
};

export type ScanResults = {
  target_url: string;
  checked_at: string;
  tls: TlsResult;
  headers: HeadersResult;
  dns: DnsResult;
  exposure: ExposureResult;
};

type TlsResult = {
  valid: boolean;
  daysUntilExpiry: number | null;
  grade: "A" | "B" | "C" | "F" | "unknown";
  issues: string[];
};

type HeadersResult = {
  present: Record<string, string>;
  missing: string[];
  issues: string[];
};

type DnsResult = {
  spf: boolean;
  dmarc: boolean;
  issues: string[];
};

type ExposureResult = {
  exposedPaths: string[];
  issues: string[];
};

// ── TLS ───────────────────────────────────────────────────────────────────────

async function checkTls(targetUrl: string): Promise<TlsResult> {
  const parsed = new URL(targetUrl);

  if (parsed.protocol !== "https:") {
    return {
      valid: false,
      daysUntilExpiry: null,
      grade: "F",
      issues: ["Site is not served over HTTPS — all traffic is unencrypted"],
    };
  }

  return new Promise<TlsResult>((resolve) => {
    const timer = setTimeout(() => {
      resolve({ valid: false, daysUntilExpiry: null, grade: "F", issues: ["TLS check timed out"] });
    }, 12_000);

    const req = https.request(
      { hostname: parsed.hostname, port: 443, method: "HEAD", rejectUnauthorized: false },
      (res) => {
        clearTimeout(timer);
        const cert = (res.socket as tls.TLSSocket).getPeerCertificate();
        res.resume();

        if (!cert?.valid_to) {
          resolve({ valid: false, daysUntilExpiry: null, grade: "F", issues: ["No TLS certificate found"] });
          return;
        }

        const issues: string[] = [];
        const expiry = new Date(cert.valid_to);
        const days = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);

        if (days < 0) issues.push("TLS certificate has expired");
        else if (days < 14) issues.push(`TLS certificate expires in ${days} days — renew immediately`);
        else if (days < 30) issues.push(`TLS certificate expires in ${days} days`);

        // Self-signed: issuer CN matches subject CN and there's no chain
        if (cert.issuer?.CN && cert.issuer.CN === cert.subject?.CN && !cert.issuer?.O?.includes("Let's Encrypt")) {
          issues.push("Self-signed TLS certificate — browsers will show a warning to visitors");
        }

        const grade: TlsResult["grade"] = days < 0 ? "F" : issues.length > 1 ? "B" : issues.length === 0 ? "A" : "B";
        resolve({ valid: days >= 0, daysUntilExpiry: days, grade, issues });
      }
    );

    req.on("error", (err) => {
      clearTimeout(timer);
      resolve({ valid: false, daysUntilExpiry: null, grade: "F", issues: [`TLS connection failed: ${err.message}`] });
    });

    req.end();
  });
}

// ── HTTP headers ──────────────────────────────────────────────────────────────

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

async function checkHeaders(targetUrl: string): Promise<HeadersResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);

  try {
    const res = await fetch(targetUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { "User-Agent": "HebridesSecurityScanner/1.0 (+https://hebridescyber.com)" },
      redirect: "follow",
    });
    clearTimeout(timer);

    const present: Record<string, string> = {};
    const missing: string[] = [];
    const issues: string[] = [];

    for (const h of SECURITY_HEADERS) {
      const val = res.headers.get(h);
      if (val) {
        present[h] = val;
        if (h === "strict-transport-security" && !val.includes("max-age=")) {
          issues.push("HSTS header is missing max-age directive");
        }
        if (h === "x-frame-options" && !["DENY", "SAMEORIGIN"].includes(val.trim().toUpperCase())) {
          issues.push(`X-Frame-Options value "${val}" is non-standard`);
        }
      } else {
        missing.push(h);
        issues.push(`Missing security header: ${h}`);
      }
    }

    // Information disclosure via Server header
    const server = res.headers.get("server");
    if (server && /apache\/|nginx\/|iis\/|php\/|python\//i.test(server)) {
      issues.push(`Server header discloses software version: ${server}`);
      present["server"] = server;
    }

    // Check for clickjacking via CSP frame-ancestors when X-Frame-Options missing
    const csp = res.headers.get("content-security-policy") ?? "";
    if (!res.headers.has("x-frame-options") && !csp.includes("frame-ancestors")) {
      issues.push("No clickjacking protection: add X-Frame-Options or CSP frame-ancestors");
    }

    return { present, missing, issues };
  } catch {
    clearTimeout(timer);
    return {
      present: {},
      missing: SECURITY_HEADERS,
      issues: ["Could not fetch HTTP headers — site may be unreachable or blocking automated requests"],
    };
  }
}

// ── DNS / email authentication ────────────────────────────────────────────────

function apexDomain(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : hostname;
}

async function checkDns(targetUrl: string): Promise<DnsResult> {
  const apex = apexDomain(new URL(targetUrl).hostname);
  const issues: string[] = [];

  let spf = false;
  try {
    const txts = await resolveTxt(apex);
    spf = txts.some((r) => r.join("").startsWith("v=spf1"));
    if (!spf) issues.push("No SPF record — your domain can be used to send spoofed email");
  } catch {
    issues.push("Could not look up SPF record (DNS error)");
  }

  let dmarc = false;
  try {
    const txts = await resolveTxt(`_dmarc.${apex}`);
    dmarc = txts.some((r) => r.join("").startsWith("v=DMARC1"));
    if (!dmarc) issues.push("No DMARC policy — phishing using your domain is possible");
    else {
      const policy = txts.find((r) => r.join("").startsWith("v=DMARC1"))?.join("") ?? "";
      if (policy.includes("p=none")) issues.push("DMARC policy is set to 'none' — switch to 'quarantine' or 'reject' for protection");
    }
  } catch {
    issues.push("No DMARC record — phishing using your domain is possible");
  }

  return { spf, dmarc, issues };
}

// ── Sensitive path exposure ───────────────────────────────────────────────────

const SENSITIVE_PATHS = [
  { path: "/.env",            severity: "critical" as Severity, label: "Environment file exposed" },
  { path: "/.env.local",      severity: "critical" as Severity, label: "Environment file exposed" },
  { path: "/.env.production", severity: "critical" as Severity, label: "Environment file exposed" },
  { path: "/.git/HEAD",       severity: "critical" as Severity, label: "Git repository exposed — source code may be readable" },
  { path: "/wp-config.php",   severity: "critical" as Severity, label: "WordPress config file exposed" },
  { path: "/config.php",      severity: "high"     as Severity, label: "Config file exposed" },
  { path: "/phpinfo.php",     severity: "high"     as Severity, label: "phpinfo() exposed — server internals are visible" },
  { path: "/server-status",   severity: "medium"   as Severity, label: "Apache server-status exposed" },
  { path: "/elmah.axd",       severity: "high"     as Severity, label: "ASP.NET error log exposed" },
];

async function checkExposure(targetUrl: string): Promise<ExposureResult> {
  const origin = new URL(targetUrl).origin;
  const exposedPaths: string[] = [];
  const issues: string[] = [];

  await Promise.allSettled(
    SENSITIVE_PATHS.map(async ({ path, severity, label }) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6_000);
      try {
        const res = await fetch(`${origin}${path}`, {
          method: "GET",
          signal: controller.signal,
          redirect: "manual",
          headers: { "User-Agent": "HebridesSecurityScanner/1.0" },
        });
        clearTimeout(timer);
        if (res.status === 200) {
          exposedPaths.push(path);
          issues.push(`${label}: ${path}`);
          void severity; // captured for future use in per-finding severity
        }
      } catch {
        clearTimeout(timer);
      }
    })
  );

  return { exposedPaths, issues };
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

export async function runAllChecks(targetUrl: string): Promise<ScanResults> {
  const [tlsR, headersR, dnsR, exposureR] = await Promise.allSettled([
    checkTls(targetUrl),
    checkHeaders(targetUrl),
    checkDns(targetUrl),
    checkExposure(targetUrl),
  ]);

  return {
    target_url: targetUrl,
    checked_at: new Date().toISOString(),
    tls:      tlsR.status      === "fulfilled" ? tlsR.value      : { valid: false, daysUntilExpiry: null, grade: "F", issues: ["TLS check failed"] },
    headers:  headersR.status  === "fulfilled" ? headersR.value  : { present: {}, missing: SECURITY_HEADERS, issues: ["Headers check failed"] },
    dns:      dnsR.status      === "fulfilled" ? dnsR.value      : { spf: false, dmarc: false, issues: ["DNS check failed"] },
    exposure: exposureR.status === "fulfilled" ? exposureR.value : { exposedPaths: [], issues: ["Exposure check failed"] },
  };
}

// ── Results → Findings ────────────────────────────────────────────────────────

export function summariseResults(results: ScanResults): { findings: Finding[] } {
  const findings: Finding[] = [];

  for (const issue of results.tls.issues) {
    const sev: Severity = issue.includes("expired") ? "critical"
      : issue.includes("renew immediately") ? "high"
      : issue.includes("days") ? "medium"
      : "high";
    findings.push({ severity: sev, title: issue, detail: "TLS/certificate configuration issue." });
  }

  for (const issue of results.headers.issues) {
    const sev: Severity = issue.includes("content-security-policy") ? "high"
      : issue.includes("version") || issue.includes("discloses") ? "low"
      : "medium";
    findings.push({ severity: sev, title: issue, detail: "HTTP security header misconfiguration." });
  }

  for (const issue of results.dns.issues) {
    findings.push({ severity: "medium", title: issue, detail: "Email authentication configuration issue." });
  }

  for (const issue of results.exposure.issues) {
    const sev: Severity = issue.toLowerCase().includes("env") || issue.toLowerCase().includes("git") || issue.toLowerCase().includes("credentials") ? "critical" : "high";
    findings.push({ severity: sev, title: issue, detail: "Sensitive resource is publicly accessible — remediate immediately." });
  }

  return { findings };
}

// ── Scoring ───────────────────────────────────────────────────────────────────

export function scoreFromFindings(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    if (f.severity === "critical") score -= 20;
    else if (f.severity === "high")     score -= 10;
    else if (f.severity === "medium")   score -= 5;
    else if (f.severity === "low")      score -= 2;
  }
  return Math.max(0, Math.min(100, score));
}

// ── AI summary ────────────────────────────────────────────────────────────────

export async function generateAiSummary(results: ScanResults, findings: Finding[]): Promise<string> {
  const endpoint   = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey     = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  const score      = scoreFromFindings(findings);

  if (endpoint && apiKey && deployment) {
    try {
      const topIssues = findings.slice(0, 5).map((f) => f.title).join("; ");
      const res = await fetch(
        `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-01`,
        {
          method: "POST",
          headers: { "api-key": apiKey, "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: [{
              role: "user",
              content: `You are a security analyst writing a 3-sentence executive summary of a website security scan. Be factual and actionable. No jargon.\n\nTarget: ${results.target_url}\nScore: ${score}/100\nTop issues: ${topIssues || "None"}\n\nSummary:`,
            }],
            max_tokens: 180,
            temperature: 0.3,
          }),
        }
      );
      if (res.ok) {
        const data = await res.json() as { choices: { message: { content: string } }[] };
        const text = data.choices[0]?.message?.content?.trim();
        if (text) return text;
      }
    } catch { /* fall through to template */ }
  }

  return templateSummary(results, findings, score);
}

function templateSummary(results: ScanResults, findings: Finding[], score: number): string {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high     = findings.filter((f) => f.severity === "high").length;
  const domain   = new URL(results.target_url).hostname;

  if (findings.length === 0) {
    return `${domain} scored ${score}/100 with no significant security issues detected. TLS, HTTP headers, DNS authentication, and common exposure paths all checked out. No immediate action required.`;
  }

  const topIssues = [...findings.filter(f => f.severity === "critical"), ...findings.filter(f => f.severity === "high")]
    .slice(0, 2).map(f => f.title.toLowerCase()).join(" and ");

  return `${domain} scored ${score}/100 with ${critical} critical and ${high} high-severity issue${high !== 1 ? "s" : ""} found. ${topIssues ? `Key concerns include ${topIssues}.` : ""} Address critical issues first — see findings below for details and remediation steps.`;
}
