// Runs the real corpus through the real scanners against the committed
// baseline — the same thing `npm run bench` does, minus the CLI wrapper. Also
// exercises every fixture site directly so a fixture can't silently rot.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CORPUS } from "./corpus";
import * as sites from "./fixtures/sites";
import { loadExpectations } from "./lib/expectations";
import { renderReport, runBenchmark } from "./lib/runner";
import { BENCH_MODULES, scanTarget } from "./lib/scan";
import { startSite } from "./lib/server";
import type { Baseline } from "./lib/scoring";

const here = path.dirname(fileURLToPath(import.meta.url));
const baseline = JSON.parse(readFileSync(path.join(here, "baseline.json"), "utf8")) as Baseline;
const expectations = loadExpectations(path.join(here, "expectations"), BENCH_MODULES);

describe("benchmark corpus", () => {
  it("has an expectation file for every target and includes the SPA catch-all false-positive class", () => {
    for (const target of CORPUS) expect(expectations.has(target.id)).toBe(true);
    const spa = expectations.get("spa-catch-all")!;
    expect(spa.mustNotFind).toContain("exposure.exposed-file:*");
  });

  it("matches the committed baseline with no hard failures", async () => {
    const report = await runBenchmark({
      corpus: CORPUS,
      expectations,
      scan: scanTarget,
      start: startSite,
      scope: BENCH_MODULES,
      baseline,
    });
    expect(report.problems).toEqual([]);
    expect(report.ok).toBe(true);
    expect(renderReport(report, baseline)).toContain("PASS");
  }, 60_000);
});

describe("fixture sites", () => {
  async function get(handler: sites.SiteHandler, pathname: string, init?: RequestInit) {
    const site = await startSite(handler);
    try {
      const res = await fetch(site.url + pathname, { redirect: "manual", ...init });
      return { status: res.status, headers: res.headers, body: await res.text() };
    } finally {
      await site.close();
    }
  }

  it("hardened serves security.txt and robots.txt, and a real 404 elsewhere", async () => {
    expect((await get(sites.hardened, "/.well-known/security.txt")).body).toContain("Contact:");
    expect((await get(sites.hardened, "/robots.txt")).status).toBe(200);
    expect((await get(sites.hardened, "/.env")).status).toBe(404);
  });

  it("spa fixtures answer 200 for any path and echo it", async () => {
    expect((await get(sites.spaCatchAll, "/.env")).body).toContain("/.env");
    expect((await get(sites.spaCatchAllNonce, "/x")).status).toBe(200);
    expect((await get(sites.spaWithLeak, "/.env")).body).toContain("STRIPE_SECRET");
    expect((await get(sites.spaWithLeak, "/backup.sql")).body).toContain("INSERT INTO");
    expect((await get(sites.spaWithLeak, "/other")).status).toBe(200);
  });

  it("soft-404 and redirect-all behave as documented", async () => {
    expect((await get(sites.soft404, "/")).status).toBe(200);
    expect((await get(sites.soft404, "/missing")).body).toContain("could not find");
    expect((await get(sites.redirectAll, "/")).status).toBe(200);
    const redirected = await get(sites.redirectAll, "/missing");
    expect(redirected.status).toBe(302);
    expect(redirected.headers.get("location")).toBe("/");
  });

  it("seeded-legacy exposes each seeded resource", async () => {
    for (const p of ["/", "/.env", "/.git/HEAD", "/.git/config", "/backup.sql", "/phpinfo.php", "/uploads/", "/backups/", "/robots.txt"]) {
      expect((await get(sites.seededLegacy, p)).status).toBe(200);
    }
    const missing = await get(sites.seededLegacy, "/nope");
    expect(missing.status).toBe(404);
    expect(missing.body).toContain("Stack trace");
    expect((await get(sites.seededLegacy, "/", { method: "OPTIONS" })).headers.get("allow")).toContain("PUT");
  });

  it("nginx-autoindex lists /assets/ only", async () => {
    expect((await get(sites.nginxAutoindex, "/assets/")).body).toContain("Index of /assets/");
    expect((await get(sites.nginxAutoindex, "/uploads/")).status).toBe(404);
  });

  it("cors-reflect echoes the request Origin only when one is sent", async () => {
    const withOrigin = await get(sites.corsReflect, "/", { headers: { origin: "https://evil.example" } });
    expect(withOrigin.headers.get("access-control-allow-origin")).toBe("https://evil.example");
    expect(withOrigin.headers.get("access-control-allow-credentials")).toBe("true");
    const without = await get(sites.corsReflect, "/");
    expect(without.headers.get("access-control-allow-origin")).toBeNull();
    expect((await get(sites.corsReflect, "/x")).status).toBe(404);
  });

  it("login fixtures behave as documented", async () => {
    const post: RequestInit = { method: "POST", body: "a=b", headers: { "content-type": "application/x-www-form-urlencoded" } };
    expect((await get(sites.loginUnthrottled, "/")).body).not.toContain("csrf_token");
    expect((await get(sites.loginUnthrottled, "/login")).status).toBe(200);
    expect((await get(sites.loginUnthrottled, "/login", post)).status).toBe(401);
    expect((await get(sites.loginUnthrottled, "/x")).status).toBe(404);

    const throttled = sites.createLoginThrottled();
    const site = await startSite(throttled);
    try {
      expect(await (await fetch(site.url + "/")).text()).toContain("csrf_token");
      expect((await fetch(site.url + "/login")).status).toBe(200);
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) statuses.push((await fetch(site.url + "/login", post)).status);
      expect(statuses).toEqual([401, 401, 429, 429]);
      expect((await fetch(site.url + "/x")).status).toBe(404);
    } finally {
      await site.close();
    }

    expect((await get(sites.spaLogin, "/login", post)).status).toBe(200);
  });
});

describe("startSite", () => {
  it("answers 500 when a handler throws, and answers HEAD without a body", async () => {
    const site = await startSite(() => {
      throw new Error("boom");
    });
    try {
      expect((await fetch(site.url)).status).toBe(500);
    } finally {
      await site.close();
    }
    const head = await get2(sites.hardened);
    expect(head).toBe("");
  });
});

async function get2(handler: sites.SiteHandler): Promise<string> {
  const site = await startSite(handler);
  try {
    return await (await fetch(site.url, { method: "HEAD" })).text();
  } finally {
    await site.close();
  }
}
