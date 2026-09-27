import { describe, it, expect } from "vitest";
import { buildFindings, PLATFORM_TLS_TECHNOLOGIES, type TestsslEntry } from "./deepTls";

const platformEntries: TestsslEntry[] = [
  { id: "cipherlist_OBSOLETED", severity: "LOW", finding: "offered" },
  { id: "FS_TLS12_sig_algs", severity: "LOW", finding: "RSA+SHA1 RSA+SHA256" },
];

function severities(entries: TestsslEntry[], platformManagedTls?: boolean) {
  return buildFindings(entries, platformManagedTls === undefined ? undefined : { platformManagedTls }).findings.map((f) => f.severity);
}

describe("deepTls platform demotion", () => {
  it("keeps testssl's severity by default — on a self-hosted server these are the operator's own config", () => {
    const s = severities(platformEntries);
    expect(s.length).toBeGreaterThan(0);
    expect(s).not.toContain("info");
    expect(s).toContain("low");
  });

  it("keeps it when the target is explicitly not platform-managed", () => {
    expect(severities(platformEntries, false)).toContain("low");
  });

  it("demotes to info only when TLS is terminated by Azure's platform", () => {
    const s = severities(platformEntries, true);
    expect(s.length).toBeGreaterThan(0);
    expect(s.every((x) => x === "info")).toBe(true);
  });

  it("never demotes checks outside the platform list, even on Azure", () => {
    const s = severities([{ id: "SSLv3", severity: "HIGH", finding: "offered (NOT ok)" }], true);
    expect(s).toContain("high");
  });

  it("recognises both Azure fingerprints", () => {
    expect([...PLATFORM_TLS_TECHNOLOGIES]).toEqual(["Azure CDN", "Azure App Service"]);
  });
});
