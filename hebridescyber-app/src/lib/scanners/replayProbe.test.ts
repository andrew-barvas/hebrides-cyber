import { describe, it, expect, vi } from "vitest";
import { createReplayBudget, MAX_REPLAY_BODY_BYTES, replayProbe, resolveReplayUrl } from "./replayProbe";
import type { Baseline } from "./httpProbe";

const TARGET = "https://www.example.co.uk";

function response(body: string, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(body, { status: init.status ?? 200, headers: init.headers });
}

function fakeFetch(res: Response | (() => Response)) {
  return vi.fn(async () => (typeof res === "function" ? res() : res)) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

describe("resolveReplayUrl", () => {
  it("resolves an absolute path and query against the target origin", () => {
    const r = resolveReplayUrl(TARGET, { path: "/search", query: { q: "x" } });
    expect("url" in r && r.url.href).toBe("https://www.example.co.uk/search?q=x");
  });

  it.each([
    ["relative path", "search"],
    ["protocol-relative host", "//evil.example/x"],
    ["backslash host trick", "/\\evil.example"],
    ["scheme in path", "https://evil.example/"],
    ["control character", "/a\u0000b"],
    ["overlong path", "/" + "a".repeat(600)],
  ])("refuses %s", (_name, path) => {
    expect("reason" in resolveReplayUrl(TARGET, { path })).toBe(true);
  });

  it("refuses too many query parameters", () => {
    const query = Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`p${i}`, "v"]));
    expect("reason" in resolveReplayUrl(TARGET, { path: "/", query })).toBe(true);
  });

  it("refuses a target that is not http(s)", () => {
    expect("reason" in resolveReplayUrl("ftp://example.com", { path: "/" })).toBe(true);
    expect("reason" in resolveReplayUrl("not a url", { path: "/" })).toBe(true);
  });

  it("allows an IP-address target against itself", () => {
    const r = resolveReplayUrl("http://203.0.113.9:8080", { path: "/x" });
    expect("url" in r && r.url.href).toBe("http://203.0.113.9:8080/x");
  });
});

describe("replayProbe", () => {
  it("returns the captured request and response for a GET", async () => {
    const fetchImpl = fakeFetch(response("hello", { headers: { "x-powered-by": "Express" } }));
    const r = await replayProbe(TARGET, { path: "/a", query: { id: "1" } }, { budget: createReplayBudget(), fetchImpl });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.request).toBe("GET /a?id=1");
    expect(r.response.status).toBe(200);
    expect(r.response.body).toBe("hello");
    expect(r.response.headers["x-powered-by"]).toBe("Express");
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://www.example.co.uk/a?id=1",
      expect.objectContaining({ method: "GET", redirect: "manual" }),
    );
  });

  it("refuses methods other than GET and HEAD without spending budget", async () => {
    const budget = createReplayBudget(1);
    const fetchImpl = fakeFetch(response(""));
    const r = await replayProbe(TARGET, { path: "/", method: "POST" as "GET" }, { budget, fetchImpl });
    expect(r.status).toBe("refused");
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(budget.remaining).toBe(1);
  });

  it("refuses non-allowlisted request headers (cookies, credentials)", async () => {
    const fetchImpl = fakeFetch(response(""));
    for (const name of ["Cookie", "Authorization", "Host"]) {
      const r = await replayProbe(TARGET, { path: "/", headers: { [name]: "x" } }, { budget: createReplayBudget(), fetchImpl });
      expect(r.status).toBe("refused");
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refuses a header value carrying a line break", async () => {
    const r = await replayProbe(TARGET, { path: "/", headers: { Origin: "https://a\r\nX: y" } }, { budget: createReplayBudget(), fetchImpl: fakeFetch(response("")) });
    expect(r.status).toBe("refused");
  });

  it("sends an allowlisted header and records it in the request", async () => {
    const fetchImpl = fakeFetch(response(""));
    const r = await replayProbe(TARGET, { path: "/", headers: { Origin: "https://evil.example" } }, { budget: createReplayBudget(), fetchImpl });
    expect(r.status === "ok" && r.request).toBe("GET /\nOrigin: https://evil.example");
  });

  it("stops once the shared budget is spent", async () => {
    const budget = createReplayBudget(2);
    const fetchImpl = fakeFetch(() => response("x"));
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await replayProbe(TARGET, { path: "/" }, { budget, fetchImpl }));
    expect(results.map((r) => r.status)).toEqual(["ok", "ok", "refused"]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("reports a redirect without following it", async () => {
    const fetchImpl = fakeFetch(response("", { status: 302, headers: { location: "https://evil.example/" } }));
    const r = await replayProbe(TARGET, { path: "/go" }, { budget: createReplayBudget(), fetchImpl });
    expect(r.status === "ok" && r.redirectTo).toBe("https://evil.example/");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("redacts Set-Cookie values", async () => {
    const res = new Response("", { headers: { "set-cookie": "sid=SECRET; HttpOnly" } });
    const r = await replayProbe(TARGET, { path: "/" }, { budget: createReplayBudget(), fetchImpl: fakeFetch(res) });
    expect(r.status === "ok" && r.response.headers["set-cookie"]).toBe("[redacted]");
    expect(JSON.stringify(r)).not.toContain("SECRET");
  });

  it("caps the captured body and flags truncation", async () => {
    const big = "a".repeat(MAX_REPLAY_BODY_BYTES * 3);
    const r = await replayProbe(TARGET, { path: "/" }, { budget: createReplayBudget(), fetchImpl: fakeFetch(response(big)) });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.response.body.length).toBe(MAX_REPLAY_BODY_BYTES);
    expect(r.response.truncated).toBe(true);
  });

  it("does not read a body for HEAD", async () => {
    const r = await replayProbe(TARGET, { path: "/", method: "HEAD" }, { budget: createReplayBudget(), fetchImpl: fakeFetch(response("ignored")) });
    expect(r.status === "ok" && r.response.body).toBe("");
  });

  it("flags a catch-all shell using the baseline, so a 200 is not read as a hit", async () => {
    const shell = "<html><body>app shell with enough content to be compared as one document, repeated. ".repeat(3) + "</body></html>";
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: shell.replace(/\s+/g, " ").trim().slice(0, 4000), servesCatchAll: true };
    const r = await replayProbe(TARGET, { path: "/.env" }, { budget: createReplayBudget(), baseline, fetchImpl: fakeFetch(response(shell)) });
    expect(r.status === "ok" && r.catchAll).toBe(true);
  });

  it("does not flag a genuinely different 200 as a catch-all", async () => {
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: "app shell ".repeat(40), servesCatchAll: true };
    const r = await replayProbe(TARGET, { path: "/.env" }, { budget: createReplayBudget(), baseline, fetchImpl: fakeFetch(response("DB_PASSWORD=hunter2\n".repeat(10))) });
    expect(r.status === "ok" && r.catchAll).toBe(false);
  });

  it("returns error, never an empty ok, when the request fails", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNRESET");
    }) as unknown as typeof fetch;
    const r = await replayProbe(TARGET, { path: "/" }, { budget: createReplayBudget(), fetchImpl });
    expect(r).toEqual({ status: "error", message: "ECONNRESET" });
  });
});
