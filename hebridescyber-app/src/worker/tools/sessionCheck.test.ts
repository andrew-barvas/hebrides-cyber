import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runSessionCheck } from "./sessionCheck";

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
