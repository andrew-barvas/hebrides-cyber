// The "check breakdown" rows on a scan report: one pass/fail line per core
// check, derived from the scanner's own stored results.
//
// This used to live inline in the report page against a hand-written guess
// at the result shapes — tls.valid/grade/issues, headers.missing,
// dns.spf as a boolean, exposure.exposedPaths — none of which the scanner
// stores. Every row therefore rendered green for every scan: "SPF ✓ ·
// DMARC ✓" for domains with neither, "No sensitive files exposed" above a
// critical .env finding. Typing these against the real result types makes
// that class of drift a compile error. Pure functions, so they're tested
// directly (report pages are excluded from coverage).
//
// Each returns null when the check didn't complete — an errored check
// claims neither pass nor fail.
import type { DnsResult, ExposureResult, HeadersResult, TlsResult } from "@/lib/scanners";

export type BreakdownRow = { label: string; pass: boolean; detail: string };

/** Matches tls.cert-expiring's threshold in scanners/index.ts. */
const CERT_WARN_DAYS = 21;

export function tlsRow(tls: TlsResult | undefined): BreakdownRow | null {
  const label = "TLS / HTTPS";
  if (tls?.status !== "checked") return null;
  // The narrow "checked but not HTTPS" variant carries no certificate data.
  if (!tls.isHttps || !("daysUntilExpiry" in tls)) return { label, pass: false, detail: "Not served over HTTPS" };

  const issues: string[] = [];
  if (tls.weakProtocol) issues.push(`weak protocol (${tls.protocol})`);
  if (tls.selfSigned) issues.push("self-signed certificate");
  const days = tls.daysUntilExpiry;
  if (days != null && days < 0) issues.push("certificate expired");
  else if (days != null && days < CERT_WARN_DAYS) issues.push("certificate expiring soon");
  if (!tls.hsts.present) issues.push("no HSTS");

  const detail = [days != null && days >= 0 ? `${days} days until expiry` : null, issues.length ? issues.join(", ") : "No issues"]
    .filter(Boolean)
    .join(" · ");
  return { label, pass: issues.length === 0, detail };
}

export function headersRow(headers: HeadersResult | undefined): BreakdownRow | null {
  if (headers?.status !== "checked") return null;
  const missing = headers.owasp.headers.filter((h) => !h.present).map((h) => h.name);
  return {
    label: "Security headers",
    pass: missing.length === 0,
    detail: missing.length === 0 ? "All recommended headers present" : `Missing: ${missing.join(", ")}`,
  };
}

export function emailRow(dns: DnsResult | undefined): BreakdownRow | null {
  if (dns?.status !== "checked") return null;
  const spf = dns.spf.present;
  const dmarc = dns.dmarc.present;
  // DKIM informs the detail but not pass/fail: a custom selector can't be
  // discovered from DNS, so "not found" never proves it's missing.
  return {
    label: "Email authentication",
    pass: spf && dmarc,
    detail: `SPF ${spf ? "✓" : "missing"} · DMARC ${dmarc ? "✓" : "missing"} · DKIM ${dns.dkim.found ? "✓" : "not found"}`,
  };
}

export function exposureRow(exposure: ExposureResult | undefined): BreakdownRow | null {
  if (exposure?.status !== "checked") return null;
  // Deliberately public files (security.txt) are reported at info severity;
  // only real exposures count against this row.
  const risky = exposure.exposed.filter((f) => f.severity !== "info");
  return {
    label: "Exposed sensitive paths",
    pass: risky.length === 0,
    detail: risky.length === 0 ? "No sensitive files exposed" : `Exposed: ${risky.map((f) => f.path).join(", ")}`,
  };
}

export function checkBreakdown(results: {
  tls?: TlsResult;
  headers?: HeadersResult;
  dns?: DnsResult;
  exposure?: ExposureResult;
}): BreakdownRow[] {
  return [tlsRow(results.tls), headersRow(results.headers), emailRow(results.dns), exposureRow(results.exposure)].filter(
    (row): row is BreakdownRow => row !== null
  );
}
