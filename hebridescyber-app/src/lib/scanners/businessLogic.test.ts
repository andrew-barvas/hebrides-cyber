import { describe, it, expect, vi, afterEach } from "vitest";
import { checkRateLimiting, postShowsCredentialHandling } from "./businessLogic";

afterEach(() => vi.unstubAllGlobals());

/** GET → getStatus for every path; POSTs answer from `posts` in order (last one repeats). */
function stubSite(getStatus: (path: string) => number, posts: (path: string) => number[]) {
  const seen = new Map<string, number>();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if ((init?.method ?? "GET") === "GET") return new Response("<html>login</html>", { status: getStatus(path) });
      const list = posts(path);
      const i = seen.get(path) ?? 0;
      seen.set(path, i + 1);
      return new Response("", { status: list[Math.min(i, list.length - 1)] });
    })
  );
}

describe("postShowsCredentialHandling", () => {
  it.each([400, 401, 403, 422, 429, 302, 303])("%i is evidence credentials were processed", (s) => {
    expect(postShowsCredentialHandling(s)).toBe(true);
  });

  // 200: a client-rendered page answers any POST with itself.
  it.each([200, 404, 405, 500, 501])("%i is not", (s) => {
    expect(postShowsCredentialHandling(s)).toBe(false);
  });
});

describe("checkRateLimiting", () => {
  // Regression: this reported "no rate limiting" for sites whose login is a
  // client-side page (credentials go to a third-party API) — there is
  // nothing at that URL to rate-limit.
  it("reports nothing for a client-rendered login page that ignores POSTs", async () => {
    stubSite(() => 200, () => [200]);
    const result = await checkRateLimiting("https://example.com");
    expect(result).toEqual({ checked: false, endpoint: null, rateLimited: false, requestsSent: 0 });
  });

  it("reports nothing when no candidate accepts POST at all", async () => {
    stubSite(() => 200, () => [405]);
    expect((await checkRateLimiting("https://example.com")).checked).toBe(false);
  });

  it("flags a real credential endpoint that never throttles", async () => {
    stubSite((p) => (p === "/login" ? 200 : 404), () => [401]);
    const result = await checkRateLimiting("https://example.com");
    expect(result).toEqual({ checked: true, endpoint: "/login", rateLimited: false, requestsSent: 5 });
  });

  it("recognises throttling on a real credential endpoint", async () => {
    stubSite((p) => (p === "/api/login" ? 200 : 404), () => [401, 401, 429]);
    const result = await checkRateLimiting("https://example.com");
    expect(result).toMatchObject({ checked: true, endpoint: "/api/login", rateLimited: true, requestsSent: 3 });
  });

  it("skips a client-rendered /login and still finds a real /api/login behind it", async () => {
    stubSite(() => 200, (p) => (p === "/api/login" ? [401] : [200]));
    const result = await checkRateLimiting("https://example.com");
    expect(result).toMatchObject({ checked: true, endpoint: "/api/login", rateLimited: false });
  });
});
