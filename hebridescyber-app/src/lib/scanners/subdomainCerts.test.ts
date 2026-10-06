import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CertificateRead } from "./tls";

const { readMock } = vi.hoisted(() => ({ readMock: vi.fn() }));
vi.mock("./tls", () => ({ readCertificate: readMock }));

import { checkSubdomainCerts, groupCertIssues, pickHosts, MAX_SUBDOMAIN_CERT_HOSTS } from "./subdomainCerts";

const entry = (name: string, notBefore = "2026-01-01T00:00:00") => ({ name, issuer: "R11", notBefore });

const cert = (host: string, overrides: Partial<CertificateRead> = {}): CertificateRead => ({
  host,
  subject: host,
  subjectAltNames: [host],
  issuer: "Let's Encrypt",
  validTo: "Dec  1 00:00:00 2026 GMT",
  daysUntilExpiry: 60,
  fingerprint: `FP:${host}`,
  trustProblem: null,
  ...overrides,
});

beforeEach(() => {
  readMock.mockReset();
});

describe("pickHosts", () => {
  it("keeps hosts on the site's registered domain, minus the site itself and wildcards", () => {
    const hosts = pickHosts("www.example.co.uk", [
      entry("www.example.co.uk"),
      entry("*.example.co.uk"),
      entry("shop.example.co.uk\napi.example.co.uk"),
      entry("example.com"),
      entry("evil-example.co.uk"),
    ]);
    expect(hosts.sort()).toEqual(["api.example.co.uk", "shop.example.co.uk"]);
  });

  it("leaves out other sites on a shared hosting domain", () => {
    expect(pickHosts("mysite.github.io", [entry("docs.mysite.github.io"), entry("someone-else.github.io")])).toEqual(["docs.mysite.github.io"]);
  });

  it("checks the most recently certified hosts first, and caps the list", () => {
    const entries = Array.from({ length: 30 }, (_, i) => entry(`h${i}.example.com`, `2025-${String((i % 12) + 1).padStart(2, "0")}-01`));
    entries.push(entry("fresh.example.com", "2026-09-30"));
    const hosts = pickHosts("example.com", entries);
    expect(hosts).toHaveLength(MAX_SUBDOMAIN_CERT_HOSTS);
    expect(hosts[0]).toBe("fresh.example.com");
  });
});

describe("groupCertIssues", () => {
  it("ignores healthy certificates and reports expired and soon-expiring ones", () => {
    const issues = groupCertIssues([
      cert("ok.example.com"),
      cert("old.example.com", { daysUntilExpiry: -40, trustProblem: "expired" }),
      cert("soon.example.com", { daysUntilExpiry: 5 }),
    ]);
    expect(issues.map((i) => [i.hosts.join(), i.state, i.daysUntilExpiry])).toEqual([
      ["old.example.com", "expired", -40],
      ["soon.example.com", "expiring", 5],
    ]);
  });

  it("reports one shared certificate once, listing every host serving it", () => {
    const wildcard = { subject: "*.example.com", fingerprint: "FP:wild", daysUntilExpiry: 3 };
    const issues = groupCertIssues([cert("b.example.com", wildcard), cert("a.example.com", wildcard)]);
    expect(issues).toEqual([expect.objectContaining({ certName: "*.example.com", hosts: ["a.example.com", "b.example.com"] })]);
  });

  it("skips the scanned site's own certificate — tls.ts already reports it", () => {
    expect(groupCertIssues([cert("a.example.com", { fingerprint: "FP:main", daysUntilExpiry: 2 })], "FP:main")).toEqual([]);
  });
});

describe("checkSubdomainCerts", () => {
  it("is not_applicable with no other hostnames, and connects to nothing", async () => {
    expect((await checkSubdomainCerts("https://example.com", [entry("example.com")])).status).toBe("not_applicable");
    expect(readMock).not.toHaveBeenCalled();
  });

  it("reads each host's certificate and reports the problems", async () => {
    readMock.mockImplementation(async (host: string) =>
      host === "gone.example.com" ? null : cert(host, host === "old.example.com" ? { daysUntilExpiry: -3, trustProblem: "expired" } : {})
    );
    const result = await checkSubdomainCerts(
      "https://example.com",
      [entry("old.example.com"), entry("ok.example.com"), entry("gone.example.com")],
      "FP:main"
    );
    expect(result).toMatchObject({ status: "checked", hostsChecked: 3, hostsAnswering: 2 });
    expect(result.status === "checked" && result.issues.map((i) => i.hosts[0])).toEqual(["old.example.com"]);
  });

  // No answer from any host is no evidence — must not read as "all fine".
  it("is an error when no host answers at all", async () => {
    readMock.mockResolvedValue(null);
    expect((await checkSubdomainCerts("https://example.com", [entry("a.example.com")])).status).toBe("error");
  });
});
