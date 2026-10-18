import { describe, it, expect, vi, afterEach } from "vitest";
import { checkWpVulnDb, compareVersions, vulnerabilityAppliesToVersion, wpVulnSeverity } from "./wpvdb";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const elementor = { slug: "elementor", name: "Elementor", version: "3.5.0" };
const yoast = { slug: "wordpress-seo", name: "Yoast SEO", version: "19.0" };

describe("version matching", () => {
  it("compares dotted versions leniently, refusing non-numeric segments", () => {
    expect(compareVersions("3.5.0", "3.6")).toBeLessThan(0);
    expect(compareVersions("v3.6", "3.6.0")).toBe(0);
    expect(compareVersions("3.10", "3.9")).toBeGreaterThan(0);
    expect(compareVersions("3.5-beta", "3.6")).toBeNull();
  });

  it("applies a vulnerability only when the install predates the fix", () => {
    expect(vulnerabilityAppliesToVersion({ fixed_in: "3.6.0" }, "3.5.0")).toBe(true);
    expect(vulnerabilityAppliesToVersion({ fixed_in: "3.6.0" }, "3.6.0")).toBe(false);
    expect(vulnerabilityAppliesToVersion({ fixed_in: null }, "99.0")).toBe(true); // unpatched upstream
    expect(vulnerabilityAppliesToVersion({ fixed_in: "3.6.0" }, "trunk")).toBe(false); // can't evidence it
  });

  it("grades RCE/SQLi/privilege escalation as critical, the rest high", () => {
    expect(wpVulnSeverity("RCE")).toBe("critical");
    expect(wpVulnSeverity("SQLI")).toBe("critical");
    expect(wpVulnSeverity("XSS")).toBe("high");
    expect(wpVulnSeverity(null)).toBe("high");
  });
});

describe("checkWpVulnDb", () => {
  it("is not_configured without a token, and not_applicable with no plugins", async () => {
    vi.stubEnv("WPSCAN_API_TOKEN", "");
    expect((await checkWpVulnDb([elementor])).status).toBe("not_configured");
    vi.stubEnv("WPSCAN_API_TOKEN", "t");
    expect((await checkWpVulnDb([])).status).toBe("not_applicable");
  });

  it("reports only the vulnerabilities that apply to the installed version", async () => {
    vi.stubEnv("WPSCAN_API_TOKEN", "t");
    const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async (url) =>
      url.endsWith("/plugins/elementor")
        ? new Response(
            JSON.stringify({
              elementor: {
                vulnerabilities: [
                  { id: 1, title: "Old XSS", fixed_in: "3.1.0", vuln_type: "XSS" },
                  { id: 2, title: "RCE in upload", fixed_in: "3.6.3", vuln_type: "RCE", references: { cve: ["2022-1329"], url: ["https://example.org/adv"] } },
                ],
              },
            })
          )
        : new Response("", { status: 404 })
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await checkWpVulnDb([elementor, yoast]);
    expect(result).toEqual({
      status: "checked",
      plugins: [
        {
          ...elementor,
          vulnerabilities: [
            { id: "2", title: "RCE in upload", fixedIn: "3.6.3", vulnType: "RCE", cveIds: ["CVE-2022-1329"], referenceUrls: ["https://example.org/adv"] },
          ],
        },
        { ...yoast, vulnerabilities: [] }, // 404: WPScan doesn't track it — nothing to report
      ],
      themes: [],
    });
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ headers: { Authorization: "Token token=t" } });
  });

  // Regression: a rate-limited lookup came back as "checked, no vulnerabilities",
  // which let the scan mark last time's plugin findings fixed.
  it("is an error, not a clean result, when any lookup fails", async () => {
    vi.stubEnv("WPSCAN_API_TOKEN", "t");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => (url.endsWith("/plugins/elementor") ? new Response("", { status: 429 }) : new Response("{}")))
    );
    expect(await checkWpVulnDb([elementor, yoast])).toEqual({
      status: "error",
      note: "WPScan lookup failed for 1 of 2 plugin(s)/theme(s): elementor",
    });
  });

  it("looks themes up at /themes/{slug} and reports them separately from plugins", async () => {
    vi.stubEnv("WPSCAN_API_TOKEN", "t");
    const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async (url) =>
      url.endsWith("/themes/astra")
        ? new Response(JSON.stringify({ astra: { vulnerabilities: [{ id: 7, title: "Stored XSS", fixed_in: "4.6.9", vuln_type: "XSS" }] } }))
        : new Response("", { status: 404 })
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await checkWpVulnDb([], [{ slug: "astra", name: "Astra", version: "4.6.0" }]);
    expect(result).toMatchObject({
      status: "checked",
      plugins: [],
      themes: [{ slug: "astra", version: "4.6.0", vulnerabilities: [{ id: "7", fixedIn: "4.6.9" }] }],
    });
    expect(fetchMock.mock.calls[0][0]).toMatch(/\/themes\/astra$/);
  });
});
