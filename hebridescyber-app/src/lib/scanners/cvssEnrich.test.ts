import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { enrichFindingsWithCvss } from "./cvssEnrich";
import type { Finding } from "./index";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "medium",
    title: "test finding",
    detail: "test detail",
    checkId: "test.check",
    ...overrides,
  };
}

describe("enrichFindingsWithCvss", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("skips findings without cveIds", async () => {
    const findings = [makeFinding()];
    await enrichFindingsWithCvss(findings);
    expect(findings[0].cvssScore).toBeUndefined();
    expect(findings[0].cvssVector).toBeUndefined();
  });

  it("skips findings with empty cveIds array", async () => {
    const findings = [makeFinding({ cveIds: [] })];
    await enrichFindingsWithCvss(findings);
    expect(findings[0].cvssScore).toBeUndefined();
  });

  it("enriches findings with CVE data from NVD", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2023-1234",
              metrics: {
                cvssMetricV31: [
                  {
                    cvssData: {
                      baseScore: 9.8,
                      vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                  },
                ],
              },
            },
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const findings = [makeFinding({ cveIds: ["CVE-2023-1234"] })];
    await enrichFindingsWithCvss(findings);

    expect(findings[0].cvssScore).toBe(9.8);
    expect(findings[0].cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  });

  it("handles NVD API errors gracefully", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 403 });
    vi.stubGlobal("fetch", mockFetch);

    const findings = [makeFinding({ cveIds: ["CVE-2023-9999"] })];
    await enrichFindingsWithCvss(findings);
    expect(findings[0].cvssScore).toBeUndefined();
  });

  it("handles fetch failures gracefully", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("network error"));
    vi.stubGlobal("fetch", mockFetch);

    const findings = [makeFinding({ cveIds: ["CVE-2023-9999"] })];
    await enrichFindingsWithCvss(findings);
    expect(findings[0].cvssScore).toBeUndefined();
  });

  it("deduplicates CVE lookups across findings", async () => {
    // Use a unique CVE ID not used by other tests to avoid module-level cache hits
    const cveId = "CVE-2023-DEDUP-TEST";
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: cveId,
              metrics: {
                cvssMetricV31: [
                  { cvssData: { baseScore: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" } },
                ],
              },
            },
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const findings = [
      makeFinding({ cveIds: [cveId], checkId: "a" }),
      makeFinding({ cveIds: [cveId], checkId: "b" }),
    ];
    await enrichFindingsWithCvss(findings);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(findings[0].cvssScore).toBe(7.5);
    expect(findings[1].cvssScore).toBe(7.5);
  });

  it("uses first matched CVE score when finding has multiple CVEs", async () => {
    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      const cveId = (url as string).match(/cveId=(CVE-[\d-]+)/)?.[1];
      const scores: Record<string, number> = {
        "CVE-2023-0001": 5.0,
        "CVE-2023-0002": 8.5,
      };
      return {
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              cve: {
                id: cveId,
                metrics: {
                  cvssMetricV31: [
                    { cvssData: { baseScore: scores[cveId!] ?? 0, vectorString: `CVSS:3.1/test/${cveId}` } },
                  ],
                },
              },
            },
          ],
        }),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const findings = [makeFinding({ cveIds: ["CVE-2023-0001", "CVE-2023-0002"] })];
    await enrichFindingsWithCvss(findings);

    // Implementation assigns the first CVE with a cached result
    expect(findings[0].cvssScore).toBe(5.0);
  });

  it("limits to 20 unique CVE lookups", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2023-0001",
              metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.0, vectorString: "v" } }] },
            },
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const findings = Array.from({ length: 25 }, (_, i) =>
      makeFinding({ cveIds: [`CVE-2023-${String(i).padStart(4, "0")}`], checkId: `check.${i}` })
    );
    await enrichFindingsWithCvss(findings);

    expect(mockFetch.mock.calls.length).toBeLessThanOrEqual(20);
  });
});
