import { describe, it, expect, vi } from "vitest";
import {
  levenshteinDistance,
  findTyposquatCandidates,
  assessTyposquatCandidates,
  buildTyposquatFinding,
  POPULAR_PACKAGES,
  MAX_TYPOSQUAT_CANDIDATES,
  type PackageRegistryMetadata,
  type TyposquatFinding,
} from "./typosquatRisk";

describe("levenshteinDistance", () => {
  it("is 0 for identical strings", () => {
    expect(levenshteinDistance("lodash", "lodash")).toBe(0);
  });

  it("is the string length for an empty counterpart", () => {
    expect(levenshteinDistance("", "abc")).toBe(3);
    expect(levenshteinDistance("abc", "")).toBe(3);
  });

  it("is 1 for a single substitution", () => {
    expect(levenshteinDistance("loaash", "loadsh")).toBe(1);
  });

  it("is 1 for a single insertion/deletion (real-world example: loadsh vs lodash)", () => {
    // loadsh -> lodash: swap positions of 'a' and 'd' is distance 2 actually;
    // use a genuine single-edit pair instead.
    expect(levenshteinDistance("reqeusts", "requests")).toBe(2);
    expect(levenshteinDistance("requests", "request")).toBe(1); // deletion
    expect(levenshteinDistance("expres", "express")).toBe(1); // deletion
  });

  it("grows with unrelated strings", () => {
    expect(levenshteinDistance("react", "django")).toBeGreaterThan(1);
  });
});

describe("findTyposquatCandidates", () => {
  it("flags an npm package one character away from a popular one", () => {
    const candidates = findTyposquatCandidates([{ ecosystem: "npm", name: "expres" }]);
    expect(candidates).toEqual([{ ecosystem: "npm", name: "expres", resembles: "express" }]);
  });

  it("flags a PyPI package one character away from a popular one", () => {
    const candidates = findTyposquatCandidates([{ ecosystem: "PyPI", name: "djago" }]); // django minus 'n'
    expect(candidates).toEqual([{ ecosystem: "PyPI", name: "djago", resembles: "django" }]);
  });

  it("does not flag the popular package itself", () => {
    expect(findTyposquatCandidates([{ ecosystem: "npm", name: "express" }])).toEqual([]);
    expect(findTyposquatCandidates([{ ecosystem: "npm", name: "Express" }])).toEqual([]); // case-insensitive
  });

  it("does not flag PyPI names that differ only by PEP 503 normalisation (-, _, . equivalence)", () => {
    expect(findTyposquatCandidates([{ ecosystem: "PyPI", name: "scikit_learn" }])).toEqual([]);
    expect(findTyposquatCandidates([{ ecosystem: "PyPI", name: "python-dateutil" }])).toEqual([]);
  });

  it("ignores ecosystems with no curated list", () => {
    expect(findTyposquatCandidates([{ ecosystem: "Go", name: "expres" }])).toEqual([]);
    expect(findTyposquatCandidates([{ ecosystem: "RubyGems", name: "djago" }])).toEqual([]);
  });

  it("ignores names shorter than the minimum length", () => {
    expect(findTyposquatCandidates([{ ecosystem: "npm", name: "ws2" }])).toEqual([]);
  });

  it("ignores unrelated package names", () => {
    expect(findTyposquatCandidates([{ ecosystem: "npm", name: "my-internal-tool" }])).toEqual([]);
  });

  it("deduplicates repeated package names", () => {
    const candidates = findTyposquatCandidates([
      { ecosystem: "npm", name: "expres" },
      { ecosystem: "npm", name: "expres" },
    ]);
    expect(candidates).toHaveLength(1);
  });

  it("every curated popular-package entry is distance 0 from itself (list sanity)", () => {
    for (const [ecosystem, names] of Object.entries(POPULAR_PACKAGES)) {
      for (const name of names) {
        expect(findTyposquatCandidates([{ ecosystem: ecosystem as "npm" | "PyPI", name }])).toEqual([]);
      }
    }
  });
});

function meta(status: "found", versionCount: number, createdAt?: string): PackageRegistryMetadata;
function meta(status: "not_found" | "error"): PackageRegistryMetadata;
function meta(status: "found" | "not_found" | "error", versionCount?: number, createdAt?: string): PackageRegistryMetadata {
  if (status === "found") return { status, versionCount: versionCount!, createdAt: createdAt ?? null };
  if (status === "not_found") return { status };
  return { status, reason: "network error" };
}

describe("assessTyposquatCandidates", () => {
  it("reports a candidate with few releases that resembles a mature package", async () => {
    const fetchMetadata = vi.fn(async (_ecosystem: "npm" | "PyPI", name: string) =>
      name === "loadsh" ? meta("found", 4, "2018-09-13T00:00:00Z") : meta("found", 117, "2012-04-23T00:00:00Z")
    );
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "loadsh", resembles: "lodash" }], fetchMetadata);
    expect(result.findings).toEqual([
      {
        ecosystem: "npm",
        name: "loadsh",
        resembles: "lodash",
        candidateVersionCount: 4,
        candidateCreatedAt: "2018-09-13T00:00:00Z",
        popularVersionCount: 117,
        popularCreatedAt: "2012-04-23T00:00:00Z",
      },
    ]);
    expect(result.checked).toBe(1);
  });

  it("does not report when the candidate has plenty of releases too", async () => {
    const fetchMetadata = vi.fn(async () => meta("found", 50));
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "expres", resembles: "express" }], fetchMetadata);
    expect(result.findings).toEqual([]);
  });

  it("does not report when the popular package itself has few releases (weak baseline)", async () => {
    const fetchMetadata = vi.fn(async (_e: "npm" | "PyPI", name: string) => (name === "candidate" ? meta("found", 2) : meta("found", 5)));
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "candidate", resembles: "resembled" }], fetchMetadata);
    expect(result.findings).toEqual([]);
  });

  it("never reports a candidate missing from the registry (404) — no evidence either way", async () => {
    const fetchMetadata = vi.fn(async (_e: "npm" | "PyPI", name: string) => (name === "loadsh" ? meta("not_found") : meta("found", 117)));
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "loadsh", resembles: "lodash" }], fetchMetadata);
    expect(result.findings).toEqual([]);
  });

  it("never reports when the popular package itself can't be found", async () => {
    const fetchMetadata = vi.fn(async (_e: "npm" | "PyPI", name: string) => (name === "lodash" ? meta("not_found") : meta("found", 2)));
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "loadsh", resembles: "lodash" }], fetchMetadata);
    expect(result.findings).toEqual([]);
  });

  it("drops a candidate on a failed lookup and notes it, without failing the whole check", async () => {
    const fetchMetadata = vi.fn(async () => meta("error"));
    const result = await assessTyposquatCandidates([{ ecosystem: "npm", name: "loadsh", resembles: "lodash" }], fetchMetadata);
    expect(result.findings).toEqual([]);
    expect(result.notes.some((n) => n.includes("1 of 1 registry lookups failed"))).toBe(true);
  });

  it("fetches each distinct name at most once even when many candidates share a resembled package", async () => {
    const fetchMetadata = vi.fn(async (_e: "npm" | "PyPI", name: string) => (name === "lodash" ? meta("found", 117) : meta("found", 2)));
    await assessTyposquatCandidates(
      [
        { ecosystem: "npm", name: "loadsh", resembles: "lodash" },
        { ecosystem: "npm", name: "lodahs", resembles: "lodash" },
      ],
      fetchMetadata
    );
    const lodashCalls = fetchMetadata.mock.calls.filter(([, name]) => name === "lodash");
    expect(lodashCalls).toHaveLength(1);
  });

  it("bounds live lookups at MAX_TYPOSQUAT_CANDIDATES and notes the overflow", async () => {
    const many = Array.from({ length: MAX_TYPOSQUAT_CANDIDATES + 5 }, (_, i) => ({
      ecosystem: "npm" as const,
      name: `candidate-${i}`,
      resembles: "express",
    }));
    const fetchMetadata = vi.fn(async () => meta("found", 50));
    const result = await assessTyposquatCandidates(many, fetchMetadata);
    expect(result.checked).toBe(MAX_TYPOSQUAT_CANDIDATES);
    expect(result.notes.some((n) => n.includes(`first ${MAX_TYPOSQUAT_CANDIDATES} of ${many.length}`))).toBe(true);
  });

  it("returns a clean empty result for no candidates", async () => {
    const fetchMetadata = vi.fn();
    const result = await assessTyposquatCandidates([], fetchMetadata);
    expect(result).toEqual({ findings: [], checked: 0, notes: [] });
    expect(fetchMetadata).not.toHaveBeenCalled();
  });
});

describe("buildTyposquatFinding", () => {
  const finding: TyposquatFinding = {
    ecosystem: "npm",
    name: "loadsh",
    resembles: "lodash",
    candidateVersionCount: 4,
    candidateCreatedAt: "2018-09-13T06:41:39.649Z",
    popularVersionCount: 117,
    popularCreatedAt: "2012-04-23T16:37:11.912Z",
  };

  it("builds a stable checkId keyed on the package name", () => {
    expect(buildTyposquatFinding(finding).checkId).toBe("dependency-manifest.typosquat-risk:loadsh");
  });

  it("is medium severity — a heuristic signal, never escalated to high/critical", () => {
    expect(buildTyposquatFinding(finding).severity).toBe("medium");
  });

  it("names both packages and their release counts in the detail text", () => {
    const detail = buildTyposquatFinding(finding).detail;
    expect(detail).toContain("loadsh");
    expect(detail).toContain("lodash");
    expect(detail).toContain("117 published releases");
    expect(detail).toContain("4 release");
    expect(detail).toContain("2018-09-13");
    expect(detail).toContain("2012-04-23");
  });

  it("carries a non-empty remediation", () => {
    expect(buildTyposquatFinding(finding).remediation).toBeTruthy();
  });

  it("formats an unknown creation date without throwing", () => {
    const unknown: TyposquatFinding = { ...finding, candidateCreatedAt: null, popularCreatedAt: null };
    const detail = buildTyposquatFinding(unknown).detail;
    expect(detail).toContain("an unknown date");
  });
});
