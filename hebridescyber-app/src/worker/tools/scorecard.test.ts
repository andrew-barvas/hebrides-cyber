import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/githubApp", () => ({ resolveGithubAuth: vi.fn(async () => ({ token: "", via: "none" })) }));

import { runScorecard, scorecardFindings, SCORECARD_API } from "./scorecard";

const BODY = {
  date: "2026-11-10",
  score: 4.2,
  checks: [
    { name: "Dangerous-Workflow", score: 0, reason: "dangerous workflow patterns detected", documentation: { url: "https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow" } },
    { name: "Branch-Protection", score: 3, reason: "branch protection is not maximal on development and all release branches" },
    { name: "Code-Review", score: 8, reason: "Found 8/10 approved changesets" },
    { name: "Token-Permissions", score: -1, reason: "internal error" },
    { name: "Fuzzing", score: 0, reason: "project is not fuzzed" },
  ],
};

function respond(routes: Record<string, () => Response>) {
  return vi.fn(async (url: string) => {
    for (const [prefix, make] of Object.entries(routes)) if (url.startsWith(prefix)) return make();
    throw new Error(`unexpected ${url}`);
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("scorecardFindings", () => {
  it("reports only the curated checks below their threshold, skipping inconclusive (-1) scores", () => {
    const findings = scorecardFindings("acme/web", BODY);
    expect(findings.map((f) => [f.checkId, f.severity])).toEqual([
      ["scorecard.dangerous-workflow:acme/web", "high"],
      ["scorecard.branch-protection:acme/web", "medium"],
    ]);
    expect(findings[0].detail).toContain("docs/checks.md#dangerous-workflow");
    expect(findings.every((f) => f.remediation)).toBe(true);
  });
});

describe("runScorecard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("scores a public repository", async () => {
    const fetchImpl = respond({
      "https://api.github.com/repos/acme/web": () => json({ private: false }),
      [`${SCORECARD_API}/acme/web`]: () => json(BODY),
    });
    const result = await runScorecard({ githubRepo: "acme/web" }, fetchImpl);
    expect(result).toMatchObject({ status: "completed", score: 4.2, scoredAt: "2026-11-10" });
    expect(result.findings).toHaveLength(2);
  });

  it("never sends a private repository's name to Scorecard", async () => {
    for (const github of [() => json({ private: true }), () => new Response("", { status: 404 })]) {
      const fetchImpl = respond({ "https://api.github.com/repos/acme/secret": github });
      const result = await runScorecard({ githubRepo: "acme/secret" }, fetchImpl);
      expect(result.status).toBe("not_applicable");
      expect(fetchImpl.mock.calls.some(([u]) => String(u).startsWith(SCORECARD_API))).toBe(false);
    }
  });

  it("is not_applicable, never clean, when Scorecard hasn't scored the repo", async () => {
    const fetchImpl = respond({
      "https://api.github.com/repos/acme/new": () => json({ private: false }),
      [`${SCORECARD_API}/acme/new`]: () => new Response("", { status: 404 }),
    });
    expect((await runScorecard({ githubRepo: "acme/new" }, fetchImpl)).status).toBe("not_applicable");
  });

  it("reports errors as errors", async () => {
    const down = respond({
      "https://api.github.com/repos/acme/web": () => json({ private: false }),
      [`${SCORECARD_API}/acme/web`]: () => new Response("", { status: 502 }),
    });
    expect((await runScorecard({ githubRepo: "acme/web" }, down)).status).toBe("error");
    expect((await runScorecard({ githubRepo: "not a repo" }, down)).status).toBe("error");
    const ghDown = respond({ "https://api.github.com/repos/acme/web": () => new Response("", { status: 403 }) });
    expect((await runScorecard({ githubRepo: "acme/web" }, ghDown)).status).toBe("error");
  });
});
