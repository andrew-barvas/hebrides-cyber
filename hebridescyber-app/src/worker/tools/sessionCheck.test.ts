import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSessionTokenQuality, runSessionCheck } from "./sessionCheck";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetchByUrl(rules: Record<string, { status: number; headers?: Map<string, string>; method?: string }>) {
  fetchMock.mockImplementation(async (url: string, opts?: RequestInit) => {
    for (const [pattern, resp] of Object.entries(rules)) {
      if (url.includes(pattern)) {
        if (resp.method && opts?.method !== resp.method) continue;
        return { status: resp.status, headers: resp.headers ?? new Map() };
      }
    }
    return { status: 404, headers: new Map() };
  });
}

describe("runSessionCheck", () => {
  it("detects missing rate limiting on login endpoint", async () => {
    mockFetchByUrl({
      "/login": { status: 401 },
    });

    const result = await runSessionCheck("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    const rateLimitFindings = result.findings.filter((f) => f.type === "no-rate-limit");
    expect(rateLimitFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag rate limiting when 429 is returned", async () => {
    fetchMock.mockImplementation(async (url: string, opts?: RequestInit) => {
      if (typeof url === "string" && url.includes("/login") && opts?.method === "POST") {
        return {
          status: 429,
          headers: new Map([["retry-after", "60"]]),
        };
      }
      if (typeof url === "string" && url.includes("/login")) {
        return { status: 200, headers: new Map() };
      }
      return { status: 404, headers: new Map() };
    });

    const result = await runSessionCheck("https://example.com");
    if (result.status !== "completed") return;
    const rateLimitFindings = result.findings.filter((f) => f.type === "no-rate-limit");
    expect(rateLimitFindings).toHaveLength(0);
  });

  // Regression: our own Next.js site. /login is a client-rendered page that
  // answers any POST with itself (200); authentication goes straight to
  // Supabase. Nothing there to rate-limit, so nothing to report.
  it("does not flag a client-rendered login page that answers POSTs with 200", async () => {
    mockFetchByUrl({ "/login": { status: 200 } });

    const result = await runSessionCheck("https://example.com");
    if (result.status !== "completed") return;
    expect(result.findings.filter((f) => f.type === "no-rate-limit")).toHaveLength(0);
    // It gives up on each such path after one POST rather than firing the
    // full 10-request burst at a page that isn't a login endpoint.
    const postsPerPath = new Map<string, number>();
    for (const [u, o] of fetchMock.mock.calls) {
      if (o?.method !== "POST") continue;
      const path = new URL(String(u)).pathname;
      postsPerPath.set(path, (postsPerPath.get(path) ?? 0) + 1);
    }
    expect(postsPerPath.get("/login")).toBe(1);
    expect(Math.max(...postsPerPath.values())).toBe(1);
  });

  it("skips a client-rendered /login and still judges a real /api/login behind it", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      const path = new URL(url).pathname;
      if (path === "/login") return { status: 200, headers: new Map() };
      if (path === "/api/login") return { status: 401, headers: new Map() };
      return { status: 404, headers: new Map() };
    });

    const result = await runSessionCheck("https://example.com");
    if (result.status !== "completed") return;
    const rateLimit = result.findings.filter((f) => f.type === "no-rate-limit");
    expect(rateLimit).toHaveLength(1);
    expect(rateLimit[0].url).toBe("/api/login");
  });

  it("detects IDOR indicators on API endpoints", async () => {
    fetchMock.mockImplementation(async (url: string, opts?: RequestInit) => {
      if (typeof url === "string" && url.includes("/api/users/1") && (!opts || opts.method !== "POST")) {
        return {
          status: 200,
          headers: new Map([["content-type", "application/json"]]),
        };
      }
      return { status: 404, headers: new Map() };
    });

    const result = await runSessionCheck("https://example.com");
    if (result.status !== "completed") return;
    const idorFindings = result.findings.filter((f) => f.type === "idor-indicator");
    expect(idorFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("returns completed with empty findings when all checks pass", async () => {
    fetchMock.mockResolvedValue({ status: 404, headers: new Map() });

    const result = await runSessionCheck("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings).toEqual([]);
  });
});

describe("checkSessionTokenQuality", () => {
  /** A site whose home page sets one session cookie, with the value chosen per request. */
  function siteIssuing(cookieName: string, valueFor: (n: number) => string, extra: string[] = []) {
    let n = 0;
    fetchMock.mockImplementation(async () => {
      const i = n++;
      return { status: 200, headers: { getSetCookie: () => [`${cookieName}=${valueFor(i)}; Path=/; HttpOnly`, ...extra], get: () => null, has: () => false } };
    });
  }

  it("flags a session cookie that counts up", async () => {
    siteIssuing("PHPSESSID", (i) => String(90000 + i));
    const findings = await checkSessionTokenQuality("https://example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ type: "weak-session-token", url: "PHPSESSID" });
    expect(findings[0].detail).toContain("count up in small steps");
  });

  it("flags a short session id", async () => {
    const alphabet = "0123456789abcdef";
    siteIssuing("sid", (i) => Array.from({ length: 6 }, (_, k) => alphabet[(i * 7 + k * 5 + i * k) % 16]).join(""));
    const findings = await checkSessionTokenQuality("https://example.com");
    expect(findings.map((f) => f.type)).toEqual(["weak-session-token"]);
  });

  it("leaves a long random session id alone", async () => {
    const chars = "0123456789abcdef";
    let seed = 12345;
    const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    siteIssuing("session", () => Array.from({ length: 40 }, () => chars[Math.floor(rand() * 16)]).join(""));
    expect(await checkSessionTokenQuality("https://example.com")).toEqual([]);
  });

  it("ignores cookies that are not session cookies, and JWT-shaped values", async () => {
    siteIssuing("_ga", (i) => String(i), ["sessionToken=eyJhbGciOiJIUzI1NiJ9.e30.abc"]);
    expect(await checkSessionTokenQuality("https://example.com")).toEqual([]);
  });

  it("reports nothing when no cookie is set, or when the requests fail", async () => {
    fetchMock.mockImplementation(async () => ({ status: 200, headers: { getSetCookie: () => [], get: () => null, has: () => false } }));
    expect(await checkSessionTokenQuality("https://example.com")).toEqual([]);
    fetchMock.mockImplementation(async () => {
      throw new Error("down");
    });
    expect(await checkSessionTokenQuality("https://example.com")).toEqual([]);
  });

  it("does not judge a cookie seen too few times", async () => {
    let n = 0;
    fetchMock.mockImplementation(async () => ({ status: 200, headers: { getSetCookie: () => (n++ < 3 ? ["sid=1" + n] : []), get: () => null, has: () => false } }));
    expect(await checkSessionTokenQuality("https://example.com")).toEqual([]);
  });

  it("does not put a token value in the finding", async () => {
    siteIssuing("PHPSESSID", (i) => String(90000 + i));
    const [finding] = await checkSessionTokenQuality("https://example.com");
    expect(JSON.stringify(finding)).not.toMatch(/9000\d/);
  });
});

describe("runSessionCheck token sampling", () => {
  it("includes a weak-session-token finding in the combined result", async () => {
    let n = 0;
    fetchMock.mockImplementation(async (url: string) => ({
      status: 404,
      headers: { getSetCookie: () => (url === "https://example.com" ? [`sid=${70000 + n++}`] : []), get: () => null, has: () => false },
    }));
    const result = await runSessionCheck("https://example.com");
    expect(result.status === "completed" && result.findings.map((f) => f.type)).toContain("weak-session-token");
  });
});
