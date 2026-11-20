import { describe, expect, it } from "vitest";
import type { FindingRow } from "./findingsView";
import { buildEstateMap, type ScanSnapshot } from "./estateMap";
import type { HttpProbeRecord } from "./scanners/hostProbe";

const rec = (host: string, statusCode: number, title: string | null = null): HttpProbeRecord => ({ input: host, url: `https://${host}/`, host, port: "443", scheme: "https", statusCode, contentLength: 1, title, webserver: null, tech: [] });
const row = (host: string, checkId: string, severity: string, over: Partial<FindingRow> = {}): FindingRow =>
  ({ key: `${host} ${checkId}`, host, checkId, severity, title: checkId, triage: null, ...over }) as unknown as FindingRow;

const scans: ScanSnapshot[] = [
  { id: "s2", target_url: "https://www.example.com", created_at: "2026-11-19", httpx: [rec("www.example.com", 200, "Home"), rec("old.example.com", 404)], tls: { status: "checked", certificateExpiresAt: "2026-12-01T00:00:00Z", daysUntilExpiry: 11, issuer: "R3" } },
  { id: "s1", target_url: "https://www.example.com", created_at: "2026-11-01", httpx: [rec("www.example.com", 500)], tls: { status: "checked", certificateExpiresAt: "2026-11-02T00:00:00Z", daysUntilExpiry: 1, issuer: "R3" } },
  { id: "s0", target_url: "https://shop.other.co.uk", created_at: "2026-10-01", httpx: null, tls: { status: "error" } },
];

describe("buildEstateMap", () => {
  const map = buildEstateMap(
    [
      { hostname: "www.example.com", kind: "domain", first_seen_at: "2026-09-01", last_seen_at: "2026-11-19" },
      { hostname: "mail.example.com", kind: "subdomain", first_seen_at: "2026-09-01", last_seen_at: "2026-11-19" },
    ],
    scans,
    [
      row("www.example.com", "network-exposure.open-port:3389", "high"),
      row("www.example.com", "network-exposure.open-port:22", "medium"),
      row("www.example.com", "headers.hsts", "low"),
      row("mail.example.com", "dns.spf-missing", "critical", { triage: { state: "false_positive", reason: "x", expiresAt: null } }),
    ],
  );

  it("groups hosts by registrable domain, the domain's own host first", () => {
    expect(map.domains.map((d) => d.domain)).toEqual(["example.com", "other.co.uk"]);
    expect(map.domains[0].hosts.map((h) => h.host)).toEqual(["mail.example.com", "old.example.com", "www.example.com"]);
  });

  it("uses the newest probe and scan for each host", () => {
    const www = map.domains[0].hosts.find((h) => h.host === "www.example.com");
    expect(www).toMatchObject({ kind: "domain", scanId: "s2", web: { statusCode: 200, title: "Home" }, certificate: { daysLeft: 11, issuer: "R3" } });
    expect(www?.exposedPorts).toEqual(["22", "3389"]);
    expect(www?.openFindings).toMatchObject({ high: 1, medium: 1, low: 1 });
  });

  it("shows unknowns as unknown, and leaves false positives out", () => {
    const mail = map.domains[0].hosts.find((h) => h.host === "mail.example.com");
    expect(mail).toMatchObject({ web: null, certificate: null, scanId: null });
    expect(mail?.openFindings.critical).toBe(0);
    const shop = map.domains[1].hosts[0];
    expect(shop).toMatchObject({ host: "shop.other.co.uk", certificate: null, scanId: "s0" });
  });

  it("totals live hosts, expiring certificates and hosts with serious issues", () => {
    expect(map.totals).toEqual({ hosts: 4, live: 2, certificatesExpiringSoon: 1, withCriticalOrHigh: 1 });
  });
});
