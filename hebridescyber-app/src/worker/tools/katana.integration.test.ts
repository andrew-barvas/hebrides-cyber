// Runs the real katana against a local site. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges (set
// KATANA_BIN to run it elsewhere). Checks against the real binary what the
// unit tests can only assume: that -jc finds routes mentioned only in a
// JavaScript file, that -cos keeps katana off logout links, and that the
// crawler's page checks then run on the JS-only page.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { runKatana } from "./katana";

const SECURE = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const html = (body: string) => `<!doctype html><html><head><title>t</title></head><body>${body}</body></html>`;

// "/" links to /about and a logout link, and loads app.js, which is the only
// place /dashboard/reports appears. That page is missing the CSP the start page sends.
const ROUTES: Record<string, { type: string; body: string; secure: boolean }> = {
  "/": { type: "text/html", body: html('<a href="/about">About</a> <a href="/account/logout">Log out</a><script src="/static/app.js"></script>'), secure: true },
  "/about": { type: "text/html", body: html("About"), secure: true },
  "/static/app.js": { type: "application/javascript", body: 'const routes=["/dashboard/reports"];fetch("/api/orders?page=1");', secure: true },
  "/dashboard/reports": { type: "text/html", body: html("Reports"), secure: false },
  "/api/orders": { type: "application/json", body: '{"orders":[]}', secure: true },
  "/robots.txt": { type: "text/plain", body: "User-agent: *\nAllow: /\n", secure: true },
};

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("katana against a local site", () => {
  let server: Server;
  const requested: string[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      requested.push(path);
      const route = ROUTES[path];
      if (!route) {
        res.writeHead(404, { "content-type": "text/html", ...SECURE });
        res.end(html("Not found"));
        return;
      }
      res.writeHead(200, { "content-type": route.type, ...(route.secure ? SECURE : {}) });
      res.end(route.body);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  });

  afterAll(() => {
    server?.close();
  });

  it("finds the JS-only page, never follows the logout link, and checks the new page", async () => {
    const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const result = await runKatana(target, [`${target}about`]);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);

    expect(result.newPages.map((u) => new URL(u).pathname)).toContain("/dashboard/reports");
    expect(result.newPages.map((u) => new URL(u).pathname)).not.toContain("/about"); // the base crawl had it
    expect(requested).not.toContain("/account/logout");

    const gap = result.findings.find((f) => f.checkId === "katana.header-gap:content-security-policy");
    expect(gap?.detail).toContain("/dashboard/reports");
  }, 200_000);

  it("is an error, not clean, when the target is down", async () => {
    const down = createServer();
    await new Promise<void>((resolve) => down.listen(0, "127.0.0.1", () => resolve()));
    const url = `http://127.0.0.1:${(down.address() as AddressInfo).port}/`;
    await new Promise((r) => down.close(r));
    expect((await runKatana(url)).status).toBe("error");
  }, 200_000);
});
