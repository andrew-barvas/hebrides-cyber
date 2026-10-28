import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import {
  checkEndOfLife,
  clearEolCache,
  collectEolCandidates,
  eolSeverity,
  evaluateVersion,
  matchEolEntry,
  type EolEntry,
} from "./endOfLife";
import type { FingerprintResult, DetectedTech } from "./fingerprint";
import type { WebAppResult } from "./webapp";

const NOW = new Date("2026-10-15T00:00:00Z");

// Trimmed from the live endoflife.date responses (2026-10-01).
const DATA: Record<string, EolEntry[]> = {
  php: [
    { cycle: "8.4", eol: "2028-12-31" },
    { cycle: "8.2", eol: "2026-12-31" },
    { cycle: "8.1", eol: "2025-12-31" },
    { cycle: "7.4", eol: "2022-11-28" },
  ],
  nginx: [
    { cycle: "1.30", eol: false },
    { cycle: "1.28", eol: "2026-04-14" },
    { cycle: "1.18", eol: "2021-04-20" },
  ],
  "apache-http-server": [
    { cycle: "2.4", eol: false },
    { cycle: "2.2", eol: "2017-07-11" },
  ],
  jquery: [
    { cycle: "4", eol: false },
    { cycle: "3", eol: false },
    { cycle: "1", eol: true },
  ],
  bootstrap: [
    { cycle: "5", eol: false },
    { cycle: "4", eol: "2023-01-01" },
  ],
  drupal: [
    { cycle: "11.3", eol: "2026-12-16" },
    { cycle: "10.6", eol: "2026-12-16" },
    { cycle: "10.5", eol: "2026-07-01" },
    { cycle: "9.5", eol: "2023-11-01" },
    { cycle: "9.4", eol: "2023-06-21" },
    { cycle: "7", eol: "2025-01-05" },
  ],
  joomla: [
    { cycle: "5", eol: "2027-10-12" },
    { cycle: "3", eol: "2023-08-17" },
  ],
  typo3: [
    { cycle: "14", eol: "2029-06-30" },
    { cycle: "11", eol: "2024-10-31" },
    { cycle: "7", eol: "2018-12-01" },
  ],
  umbraco: [
    { cycle: "17", eol: "2028-11-27" },
    { cycle: "8", eol: "2025-02-24" },
  ],
  angular: [
    { cycle: "20", eol: "2026-11-28" },
    { cycle: "15", eol: "2024-05-18" },
  ],
};

function serveEol(overrides: Record<string, number> = {}) {
  const fetchMock = vi.fn(async (url: string) => {
    const product = decodeURIComponent(url.match(/api\/(.+)\.json$/)![1]);
    if (overrides[product]) return new Response("", { status: overrides[product] });
    return DATA[product] ? new Response(JSON.stringify(DATA[product])) : new Response("", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const tech = (name: string, version: string | null, extra: Partial<DetectedTech> = {}): DetectedTech => ({
  name,
  category: "x",
  version,
  confidence: "high",
  source: "header",
  ...extra,
});
const fp = (...technologies: DetectedTech[]): FingerprintResult => ({ status: "checked", technologies, riskySoftware: [] });
const noWebapp = null;

beforeEach(() => clearEolCache());
afterEach(() => vi.unstubAllGlobals());

describe("evaluateVersion", () => {
  it("places a full version on its major.minor cycle", () => {
    expect(evaluateVersion(DATA.php, "7.4.33", NOW)).toEqual({ state: "unsupported", cycle: "7.4", eolDate: "2022-11-28", daysOverdue: 1417 });
    expect(evaluateVersion(DATA.php, "8.4.1", NOW)).toEqual({ state: "supported", cycle: "8.4" });
  });

  it("falls back to a major cycle", () => {
    expect(evaluateVersion(DATA.jquery, "3.7.1", NOW)).toEqual({ state: "supported", cycle: "3" });
    // EOL with no date: only very old cycles have that.
    expect(evaluateVersion(DATA.jquery, "1.12.4", NOW)).toEqual({ state: "unsupported", cycle: "1", eolDate: null, daysOverdue: null });
  });

  it("gives a heads-up inside 90 days", () => {
    expect(evaluateVersion(DATA.php, "8.2.20", NOW)).toEqual({ state: "approaching", cycle: "8.2", eolDate: "2026-12-31", daysLeft: 77 });
  });

  it("treats the EOL day itself as unsupported", () => {
    expect(evaluateVersion(DATA.php, "8.2.0", new Date("2026-12-31T00:00:00Z"))?.state).toBe("unsupported");
  });

  it("judges a bare major only when every minor in it agrees", () => {
    expect(evaluateVersion(DATA.drupal, "9", NOW)).toEqual({ state: "unsupported", cycle: "9.x", eolDate: "2023-11-01", daysOverdue: 1079 });
    // 10.5 is past EOL but 10.6 isn't: we can't tell which the site runs.
    expect(evaluateVersion(DATA.drupal, "10", NOW)).toBeNull();
    expect(evaluateVersion(DATA.drupal, "7", NOW)?.state).toBe("unsupported");
  });

  it("reports nothing for a version it can't place", () => {
    expect(evaluateVersion(DATA.nginx, "1.19.2", NOW)).toBeNull(); // no 1.19 cycle in the data
    expect(evaluateVersion(DATA.php, "trunk", NOW)).toBeNull();
    // "1.2" must never match cycle "1.28".
    expect(evaluateVersion(DATA.nginx, "1.2.9", NOW)).toBeNull();
  });
});

describe("eolSeverity", () => {
  it("is sure of server software only when no distribution is involved", () => {
    expect(eolSeverity("platform", 1417, null)).toBe("high");
    expect(eolSeverity("platform", 180, null)).toBe("medium");
    expect(eolSeverity("platform", 1417, "Ubuntu")).toBe("low");
  });

  it("grades CMSes and client libraries by how long they've been unsupported", () => {
    expect(eolSeverity("application", 1079, null)).toBe("high");
    expect(eolSeverity("application", 30, null)).toBe("medium");
    expect(eolSeverity("library", null, null)).toBe("medium");
    expect(eolSeverity("library", 100, null)).toBe("low");
  });
});

describe("collectEolCandidates", () => {
  it("takes versioned, mapped technologies and keeps the distribution hint", () => {
    const candidates = collectEolCandidates(
      fp(tech("PHP", "7.4.3", { packagedBy: "Ubuntu" }), tech("Nginx", null), tech("Cloudflare", null), tech("WordPress", "6.4")),
      noWebapp
    );
    expect(candidates).toEqual([{ tech: "PHP", version: "7.4.3", packagedBy: "Ubuntu" }]);
  });

  it("prefers webapp's more precise versions and skips libraries it already reported", () => {
    const webapp = {
      status: "checked",
      drupal: { version: "9.5.11" },
      joomla: { version: "3.10.12" },
      jsLibraries: [
        { name: "Bootstrap", version: "4.6.2", isVulnerable: false, reason: "" },
        { name: "jQuery", version: "1.12.4", isVulnerable: true, reason: "" },
        { name: "Moment.js", version: "unknown", isVulnerable: false, reason: "" },
      ],
    } as unknown as WebAppResult;
    const candidates = collectEolCandidates(fp(tech("Drupal", "9", { source: "html" }), tech("jQuery", "1.12.4", { source: "html" })), webapp);
    expect(candidates).toEqual([
      { tech: "Drupal", version: "9.5.11" },
      { tech: "Joomla", version: "3.10.12" },
      { tech: "Bootstrap", version: "4.6.2" },
    ]);
  });
});

describe("checkEndOfLife: TYPO3 and Umbraco", () => {
  it("reports an out-of-support TYPO3 or Umbraco release the page shows a version for", async () => {
    serveEol();
    const result = await checkEndOfLife(fp(tech("TYPO3", "7.6.32", { source: "html" }), tech("Umbraco", "8.18.14"), tech("Moodle", null)), noWebapp, NOW);
    if (result.status !== "checked") throw new Error(JSON.stringify(result));
    expect(result.items.map((i) => i.product).sort()).toEqual(["typo3", "umbraco"]);
    expect(result.evaluated.sort()).toEqual(["TYPO3", "Umbraco"]); // Moodle has no version, so is not evaluated
  });

  it("stays silent for a supported release, and for a version no cycle covers", async () => {
    serveEol();
    const supported = await checkEndOfLife(fp(tech("TYPO3", "14.0.1", { source: "html" }), tech("Umbraco", "17.1.0")), noWebapp, NOW);
    if (supported.status !== "checked") throw new Error(JSON.stringify(supported));
    expect(supported.items).toEqual([]);
    expect(supported.evaluated.sort()).toEqual(["TYPO3", "Umbraco"]);
    // TYPO3 6.2 is older than every cycle endoflife.date lists: no verdict, not a guess.
    const unplaced = await checkEndOfLife(fp(tech("TYPO3", "6.2", { source: "html" })), noWebapp, NOW);
    if (unplaced.status !== "checked") throw new Error(JSON.stringify(unplaced));
    expect(unplaced.items).toEqual([]);
    expect(unplaced.evaluated).toEqual([]);
  });
});

describe("checkEndOfLife", () => {
  it("is not_applicable when nothing versioned was detected, and fetches nothing", async () => {
    const fetchMock = serveEol();
    expect((await checkEndOfLife(fp(tech("React", null)), noWebapp, NOW)).status).toBe("not_applicable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports unsupported and approaching software, and lists what it evaluated", async () => {
    serveEol();
    const result = await checkEndOfLife(
      fp(tech("PHP", "8.2.20"), tech("Apache", "2.2.15"), tech("Angular", "20.1"), tech("jQuery", "3.7.1", { source: "html" })),
      noWebapp,
      NOW
    );
    if (result.status !== "checked") throw new Error(JSON.stringify(result));
    expect(result.evaluated).toEqual(["PHP", "Apache", "Angular", "jQuery"]);
    expect(result.items.map((i) => [i.product, i.state, i.cycle])).toEqual([
      ["php", "approaching", "8.2"],
      ["apache-http-server", "unsupported", "2.2"],
      ["angular", "approaching", "20"],
    ]);
  });

  it("gives no countdown for a distribution package, whose support window isn't upstream's", async () => {
    serveEol();
    const result = await checkEndOfLife(fp(tech("PHP", "8.2.20", { packagedBy: "Debian" })), noWebapp, NOW);
    expect(result).toEqual({ status: "checked", items: [], evaluated: ["PHP"] });
  });

  // An outage must not read as "nothing is end-of-life".
  it("is an error when any lookup fails, and doesn't cache the failure", async () => {
    serveEol({ nginx: 503 });
    const input = fp(tech("PHP", "7.4.3"), tech("Nginx", "1.18.0"));
    expect(await checkEndOfLife(input, noWebapp, NOW)).toEqual({ status: "error", note: "endoflife.date lookup failed for: nginx" });

    serveEol();
    const retry = await checkEndOfLife(input, noWebapp, NOW);
    expect(retry.status === "checked" && retry.items.map((i) => i.product)).toEqual(["php", "nginx"]);
  });

  it("caches successful lookups per product", async () => {
    const fetchMock = serveEol();
    await checkEndOfLife(fp(tech("PHP", "7.4.3")), noWebapp, NOW);
    await checkEndOfLife(fp(tech("PHP", "8.4.1")), noWebapp, NOW);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("matchEolEntry (Docker base images)", () => {
  const debian: EolEntry[] = [
    { cycle: "12", eol: "2026-06-10", codename: "Bookworm" },
    { cycle: "11", eol: "2024-08-14", codename: "Bullseye" },
  ];

  it("matches numeric tags first, then codenames", () => {
    expect(matchEolEntry(debian, "11-slim")?.cycle).toBe("11");
    expect(matchEolEntry(debian, "bookworm-slim")?.cycle).toBe("12");
    expect(matchEolEntry(debian, "sid")).toBeNull();
  });
});
