import { describe, it, expect } from "vitest";
import {
  missingRemediableHeaders,
  editStaticWebAppConfig,
  editVercelJson,
  editNetlifyToml,
  editNextConfig,
  REMEDIABLE_HEADERS,
} from "./configFixes";

const ALL_MISSING = REMEDIABLE_HEADERS.map((h) => ({ name: h.name, present: false }));

describe("missingRemediableHeaders", () => {
  it("returns only the remediable headers that are absent, ignoring present ones and non-remediable misses", () => {
    const owasp = [
      { name: "strict-transport-security", present: false },
      { name: "x-content-type-options", present: true },
      { name: "x-frame-options", present: false },
      { name: "referrer-policy", present: true },
      { name: "content-security-policy", present: false }, // not remediable — excluded on purpose
      { name: "permissions-policy", present: false }, // not in the no-regret set
    ];
    expect(missingRemediableHeaders(owasp).map((h) => h.name)).toEqual(["strict-transport-security", "x-frame-options"]);
  });

  it("is case-insensitive on header names", () => {
    expect(missingRemediableHeaders([{ name: "X-Frame-Options", present: false }]).map((h) => h.label)).toEqual(["X-Frame-Options"]);
  });

  it("returns nothing when every remediable header is present", () => {
    expect(missingRemediableHeaders(REMEDIABLE_HEADERS.map((h) => ({ name: h.name, present: true })))).toEqual([]);
  });
});

describe("editStaticWebAppConfig", () => {
  it("adds missing headers into globalHeaders and preserves other config", () => {
    const raw = JSON.stringify({ navigationFallback: { rewrite: "/index.html" }, globalHeaders: { "X-Frame-Options": "SAMEORIGIN" } }, null, 2);
    const res = editStaticWebAppConfig(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    const parsed = JSON.parse(res.updated);
    expect(parsed.globalHeaders["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");
    expect(parsed.globalHeaders["X-Content-Type-Options"]).toBe("nosniff");
    expect(parsed.navigationFallback.rewrite).toBe("/index.html"); // untouched
    expect(res.applied).not.toContain("X-Frame-Options"); // already present, not re-added
  });

  it("creates globalHeaders when the file has none", () => {
    const res = editStaticWebAppConfig("{}", missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    expect(Object.keys(JSON.parse(res.updated).globalHeaders)).toHaveLength(4);
  });

  it("is a noop when every desired header is already set (case-insensitive)", () => {
    const raw = JSON.stringify({ globalHeaders: { "strict-transport-security": "x", "x-content-type-options": "nosniff", "X-FRAME-OPTIONS": "DENY", "Referrer-Policy": "no-referrer" } });
    expect(editStaticWebAppConfig(raw, missingRemediableHeaders(ALL_MISSING)).status).toBe("noop");
  });

  it("skips invalid JSON rather than throwing", () => {
    expect(editStaticWebAppConfig("{ not json", missingRemediableHeaders(ALL_MISSING)).status).toBe("skip");
  });
});

describe("editVercelJson", () => {
  it("merges into an existing catch-all headers entry", () => {
    const raw = JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] }] }, null, 2);
    const res = editVercelJson(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    const entry = JSON.parse(res.updated).headers[0];
    const keys = entry.headers.map((h: { key: string }) => h.key);
    expect(keys).toContain("Strict-Transport-Security");
    expect(keys.filter((k: string) => k.toLowerCase() === "x-frame-options")).toHaveLength(1); // not duplicated
    expect(res.applied).not.toContain("X-Frame-Options");
  });

  it("adds a new catch-all entry when there is no headers array", () => {
    const res = editVercelJson("{}", missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    const parsed = JSON.parse(res.updated);
    expect(parsed.headers[0].source).toBe("/(.*)");
    expect(parsed.headers[0].headers).toHaveLength(4);
  });

  it("skips invalid JSON", () => {
    expect(editVercelJson("nope", missingRemediableHeaders(ALL_MISSING)).status).toBe("skip");
  });
});

describe("editNetlifyToml", () => {
  it("appends a headers block for the headers not already named in the file", () => {
    const raw = ['[[headers]]', '  for = "/*"', "  [headers.values]", '    X-Frame-Options = "DENY"', ""].join("\n");
    const res = editNetlifyToml(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    expect(res.updated).toContain('Strict-Transport-Security = "max-age=31536000; includeSubDomains"');
    expect(res.applied).not.toContain("X-Frame-Options"); // already named in the file
    expect(res.updated.startsWith(raw.slice(0, 12))).toBe(true); // original kept at the top
  });

  it("is a noop when all desired headers already appear in the file", () => {
    const raw = REMEDIABLE_HEADERS.map((h) => `${h.label} = "x"`).join("\n");
    expect(editNetlifyToml(raw, missingRemediableHeaders(ALL_MISSING)).status).toBe("noop");
  });
});

describe("editNextConfig", () => {
  it("injects headers() into an `export default {}` config", () => {
    const raw = "/** @type {import('next').NextConfig} */\nexport default {\n  reactStrictMode: true,\n};\n";
    const res = editNextConfig(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    expect(res.updated).toContain("async headers()");
    expect(res.updated).toContain('{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" }');
    expect(res.updated).toContain("reactStrictMode: true"); // original preserved
  });

  it("injects into `const nextConfig = {}` shape", () => {
    const raw = "const nextConfig = {\n  poweredByHeader: false,\n};\nexport default nextConfig;\n";
    const res = editNextConfig(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
    if (res.status !== "edited") return;
    expect(res.updated).toContain("async headers()");
  });

  it("injects into `module.exports = {}` shape", () => {
    const res = editNextConfig("module.exports = {\n};\n", missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("edited");
  });

  it("skips when the config already defines headers()", () => {
    const raw = "export default {\n  async headers() { return []; },\n};\n";
    const res = editNextConfig(raw, missingRemediableHeaders(ALL_MISSING));
    expect(res.status).toBe("skip");
    if (res.status !== "skip") return;
    expect(res.reason).toContain("already defines headers()");
  });

  it("skips a shape it can't locate safely", () => {
    const raw = "export default withSentry(makeConfig(process.env));\n";
    expect(editNextConfig(raw, missingRemediableHeaders(ALL_MISSING)).status).toBe("skip");
  });
});
