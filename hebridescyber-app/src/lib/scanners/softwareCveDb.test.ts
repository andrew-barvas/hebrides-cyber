import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSoftwareCveDb, checkWordPressCoreCves, checkNvdCpeVulnerabilities } from "./softwareCveDb";
import type { RiskyTech } from "./fingerprint";

function risky(overrides: Partial<RiskyTech>): RiskyTech {
  return { name: "PHP", version: "7.4.0", reason: "test", ...overrides };
}

function nvdResponse(cves: Array<{ id: string; score: number; description?: string }>) {
  return {
    ok: true,
    json: async () => ({
      vulnerabilities: cves.map((c) => ({
        cve: {
          id: c.id,
          descriptions: [{ lang: "en", value: c.description ?? "test description" }],
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: c.score } }],
          },
        },
      })),
    }),
  };
}

describe("softwareCveDb", () => {
  beforeEach(() => {
    delete process.env.WPSCAN_API_TOKEN;
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe("checkSoftwareCveDb", () => {
    it("returns not_applicable for an empty riskySoftware list", async () => {
      const result = await checkSoftwareCveDb([]);
      expect(result.status).toBe("not_applicable");
    });

    it("returns not_applicable when riskySoftware has no WordPress/PHP/Apache entries", async () => {
      const result = await checkSoftwareCveDb([risky({ name: "jQuery", version: "2.1.0" })]);
      expect(result.status).toBe("not_applicable");
    });

    it("degrades cleanly with no findings when a WordPress entry is present but WPSCAN_API_TOKEN is unset", async () => {
      delete process.env.WPSCAN_API_TOKEN;
      const result = await checkSoftwareCveDb([risky({ name: "WordPress", version: "5.4" })]);
      expect(result.status).toBe("checked");
      if (result.status === "checked") {
        expect(result.findings).toEqual([]);
      }
    });

    it("produces one bundled Finding with both cveIds for a PHP entry with two mocked NVD CVEs", async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        nvdResponse([
          { id: "CVE-2021-0001", score: 5.0 },
          { id: "CVE-2021-0002", score: 6.0 },
        ])
      );
      vi.stubGlobal("fetch", mockFetch);

      const result = await checkSoftwareCveDb([risky({ name: "PHP", version: "7.4.0" })]);
      expect(result.status).toBe("checked");
      if (result.status === "checked") {
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].cveIds).toEqual(
          expect.arrayContaining(["CVE-2021-0001", "CVE-2021-0002"])
        );
        expect(result.findings[0].cveIds).toHaveLength(2);
        expect(result.findings[0].checkId).toBe("softwareCveDb.nvdCpe:php-php:7.4.0");
      }
    });

    it("still returns findings from other items when one lookup rejects (Promise.allSettled)", async () => {
      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes("php")) {
          throw new Error("network error");
        }
        return nvdResponse([{ id: "CVE-2022-9999", score: 8.0 }]);
      });
      vi.stubGlobal("fetch", mockFetch);

      const result = await checkSoftwareCveDb([
        risky({ name: "PHP", version: "7.4.0" }),
        risky({ name: "Apache", version: "2.2.0" }),
      ]);

      expect(result.status).toBe("checked");
      if (result.status === "checked") {
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].checkId).toBe("softwareCveDb.nvdCpe:apache-http_server:2.2.0");
      }
    });

    it("skips entries with no detected version", async () => {
      const result = await checkSoftwareCveDb([risky({ name: "PHP", version: "" })]);
      // version === "" is falsy, so no task is scheduled for it.
      expect(result.status).toBe("not_applicable");
    });
  });

  describe("severity bundling", () => {
    it("returns critical when any CVSS score >= 9", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          nvdResponse([
            { id: "CVE-2020-0001", score: 5.0 },
            { id: "CVE-2020-0002", score: 9.8 },
          ])
        )
      );
      const findings = await checkNvdCpeVulnerabilities("apache", "http_server", "2.2.0", "Apache");
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("returns high when the max CVSS score is >= 7 and < 9", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(nvdResponse([{ id: "CVE-2020-0003", score: 7.5 }]))
      );
      const findings = await checkNvdCpeVulnerabilities("php", "php", "7.4.0", "PHP");
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe("high");
    });

    it("returns medium when the max CVSS score is below 7", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(nvdResponse([{ id: "CVE-2020-0004", score: 4.3 }]))
      );
      const findings = await checkNvdCpeVulnerabilities("php", "php", "7.4.0", "PHP");
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe("medium");
    });

    it("returns no findings when NVD returns nothing", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ vulnerabilities: [] }) }));
      const findings = await checkNvdCpeVulnerabilities("apache", "http_server", "2.4.49", "Apache");
      expect(findings).toEqual([]);
    });

    it("returns no findings when NVD request fails", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
      const findings = await checkNvdCpeVulnerabilities("apache", "http_server", "2.4.49", "Apache");
      expect(findings).toEqual([]);
    });
  });

  describe("checkWordPressCoreCves", () => {
    it("returns [] silently when WPSCAN_API_TOKEN is not set", async () => {
      delete process.env.WPSCAN_API_TOKEN;
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const findings = await checkWordPressCoreCves("5.4");
      expect(findings).toEqual([]);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("returns a Finding per applicable vulnerability when WPSCAN_API_TOKEN is set", async () => {
      process.env.WPSCAN_API_TOKEN = "test-token";
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            "5.4": {
              vulnerabilities: [
                {
                  id: 12345,
                  title: "Core XSS vulnerability",
                  fixed_in: "5.4.2",
                  vuln_type: "XSS",
                  references: { cve: ["2021-1234"] },
                },
              ],
            },
          }),
        })
      );

      const findings = await checkWordPressCoreCves("5.4");
      expect(findings).toHaveLength(1);
      expect(findings[0].cveIds).toEqual(["CVE-2021-1234"]);
      expect(findings[0].checkId).toBe("softwareCveDb.wordpressCore:12345");

      delete process.env.WPSCAN_API_TOKEN;
    });

    it("skips vulnerabilities that don't apply to the installed version", async () => {
      process.env.WPSCAN_API_TOKEN = "test-token";
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            "6.5": {
              vulnerabilities: [
                {
                  id: 1,
                  title: "Old fixed issue",
                  fixed_in: "6.0",
                  vuln_type: "XSS",
                  references: { cve: [] },
                },
              ],
            },
          }),
        })
      );

      // Installed version 6.5 is newer than fixed_in 6.0, so this shouldn't apply.
      const findings = await checkWordPressCoreCves("6.5");
      expect(findings).toEqual([]);

      delete process.env.WPSCAN_API_TOKEN;
    });
  });
});
