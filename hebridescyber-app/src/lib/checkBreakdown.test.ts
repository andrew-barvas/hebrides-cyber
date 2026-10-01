import { describe, it, expect } from "vitest";
import { checkBreakdown, emailRow, exposureRow, headersRow, tlsRow } from "./checkBreakdown";
import type { DnsResult, ExposureResult, HeadersResult, TlsResult } from "@/lib/scanners";

function tls(overrides: Record<string, unknown> = {}): TlsResult {
  return {
    status: "checked",
    isHttps: true,
    protocol: "TLSv1.3",
    weakProtocol: false,
    selfSigned: false,
    certificateExpiresAt: "2027-03-04T23:59:59Z",
    daysUntilExpiry: 156,
    issuer: "DigiCert Inc",
    hsts: { present: true, adequate: true, maxAge: 31536000 },
    ...overrides,
  } as TlsResult;
}

function headers(present: Record<string, boolean>): HeadersResult {
  return {
    status: "checked",
    owasp: { headers: Object.entries(present).map(([name, p]) => ({ name, present: p, value: p ? "x" : null })) },
  } as unknown as HeadersResult;
}

function dns(spf: boolean, dmarc: boolean, dkim = true): DnsResult {
  return { status: "checked", spf: { present: spf }, dmarc: { present: dmarc }, dkim: { found: dkim } } as unknown as DnsResult;
}

describe("tlsRow", () => {
  it("passes a healthy certificate and shows days left", () => {
    expect(tlsRow(tls())).toEqual({ label: "TLS / HTTPS", pass: true, detail: "156 days until expiry · No issues" });
  });

  it.each([
    [{ weakProtocol: true, protocol: "TLSv1.0" }, "weak protocol (TLSv1.0)"],
    [{ selfSigned: true }, "self-signed certificate"],
    [{ daysUntilExpiry: 10 }, "certificate expiring soon"],
    [{ hsts: { present: false, adequate: false, maxAge: null } }, "no HSTS"],
    [{ trustProblem: "hostname-mismatch" }, "certificate doesn't cover this hostname"],
    [{ trustProblem: "incomplete-chain" }, "incomplete certificate chain"],
    [{ trustProblem: "untrusted" }, "untrusted certificate"],
    [{ trustProblem: "expired" }, "certificate expired"],
  ])("fails %o", (overrides, expected) => {
    const row = tlsRow(tls(overrides))!;
    expect(row.pass).toBe(false);
    expect(row.detail).toContain(expected);
  });

  it("calls an expired certificate expired, not 'expiring soon'", () => {
    const row = tlsRow(tls({ daysUntilExpiry: -3 }))!;
    expect(row.detail).toContain("certificate expired");
    expect(row.detail).not.toContain("expiring soon");
    expect(row.detail).not.toContain("days until expiry");
  });

  it("fails a site that isn't served over HTTPS", () => {
    expect(tlsRow({ status: "checked", isHttps: false, note: "http only" } as TlsResult)).toMatchObject({
      pass: false,
      detail: "Not served over HTTPS",
    });
  });
});

describe("headersRow", () => {
  it("names what's missing", () => {
    expect(headersRow(headers({ "strict-transport-security": true, "content-security-policy": false }))).toEqual({
      label: "Security headers",
      pass: false,
      detail: "Missing: content-security-policy",
    });
  });

  it("passes when everything is present", () => {
    expect(headersRow(headers({ "x-content-type-options": true }))!.pass).toBe(true);
  });
});

// The bug this module replaced: `dns.spf` is an object, so reading it as a
// boolean made every scan say "SPF ✓ · DMARC ✓".
describe("emailRow", () => {
  it("fails, and says so, when SPF and DMARC are missing", () => {
    expect(emailRow(dns(false, false, false))).toEqual({
      label: "Email authentication",
      pass: false,
      detail: "SPF missing · DMARC missing · DKIM not found",
    });
  });

  it("passes on SPF + DMARC, without requiring DKIM (a custom selector can't be seen)", () => {
    expect(emailRow(dns(true, true, false))).toMatchObject({ pass: true, detail: "SPF ✓ · DMARC ✓ · DKIM not found" });
  });
});

describe("exposureRow", () => {
  const exposure = (files: { path: string; severity: string }[]) =>
    ({ status: "checked", securityTxt: true, exposed: files.map((f) => ({ ...f, name: f.path, hint: "" })) }) as ExposureResult;

  it("fails on a real exposure and names the path", () => {
    expect(exposureRow(exposure([{ path: "/.env", severity: "critical" }]))).toMatchObject({ pass: false, detail: "Exposed: /.env" });
  });

  it("doesn't count deliberately public files like security.txt", () => {
    expect(exposureRow(exposure([{ path: "/.well-known/security.txt", severity: "info" }]))!.pass).toBe(true);
  });
});

describe("checkBreakdown", () => {
  it("omits checks that errored or predate the scan, rather than passing them", () => {
    const rows = checkBreakdown({
      tls: tls(),
      headers: { status: "error", note: "timeout" } as HeadersResult,
      dns: undefined,
      exposure: { status: "error", note: "x" } as ExposureResult,
    });
    expect(rows.map((r) => r.label)).toEqual(["TLS / HTTPS"]);
  });
});
