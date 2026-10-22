// Drift guard for the OpenAPI document: the spec is hand-maintained, so this
// is what keeps it honest. Adding a route under src/pages/api/v1 without a
// path here (or documenting a method the route never handles) fails CI.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { z } from "zod";
import { buildOpenApiSpec } from "./spec";
import { buildScanReport, pendingScanReport } from "../scanReport";
import type { Finding } from "../scanners";

const V1_DIR = join(process.cwd(), "src", "pages", "api", "v1");
const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

const spec = buildOpenApiSpec("https://api.example.test/api/v1");
type Operation = { operationId?: string; responses?: Record<string, unknown>; parameters?: Array<{ name: string; in: string }> };
const paths = spec.paths as unknown as Record<string, Record<string, Operation>>;

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full) : /\.ts$/.test(name) ? [full] : [];
  });
}

/** scans/[id]/export.ts → /scans/{id}/export */
function routePath(file: string): string {
  const rel = relative(V1_DIR, file).split(sep).join("/").replace(/\.ts$/, "");
  return "/" + rel.replace(/\[(\w+)\]/g, "{$1}");
}

// The spec endpoint describes itself; it is not part of the described surface.
const routes = listFiles(V1_DIR)
  .filter((f) => !f.endsWith("openapi.json.ts"))
  .map((file) => ({ path: routePath(file), source: readFileSync(file, "utf8") }));

const collectRefs = (node: unknown, out: string[] = []): string[] => {
  if (Array.isArray(node)) node.forEach((n) => collectRefs(n, out));
  else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "$ref" && typeof v === "string") out.push(v);
      else collectRefs(v, out);
    }
  }
  return out;
};

describe("OpenAPI spec", () => {
  it("finds the routes (guards against passing vacuously)", () => {
    expect(routes.length).toBeGreaterThanOrEqual(7);
  });

  it("describes every /api/v1 route file, and nothing that has no route", () => {
    expect(Object.keys(paths).sort()).toEqual(routes.map((r) => r.path).sort());
  });

  it.each(routes.map((r) => [r.path, r.source] as const))("%s documents exactly the methods its handler serves", (path, source) => {
    // A handler names the methods it serves as string literals ("GET", "POST"…).
    const served = HTTP_METHODS.filter((m) => new RegExp(`["']${m}["']`).test(source));
    const documented = Object.keys(paths[path]).map((m) => m.toUpperCase());
    expect(documented.sort()).toEqual([...served].sort());
  });

  it("declares every path parameter the template uses, and no others", () => {
    for (const [path, ops] of Object.entries(paths)) {
      const inPath = [...path.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
      for (const [method, op] of Object.entries(ops)) {
        const declared = (op.parameters ?? []).filter((p) => p.in === "path").map((p) => p.name).sort();
        expect(declared, `${method.toUpperCase()} ${path}`).toEqual(inPath);
      }
    }
  });

  it("gives every operation a unique operationId and a 401", () => {
    const ids: string[] = [];
    for (const [path, ops] of Object.entries(paths)) {
      for (const [method, op] of Object.entries(ops)) {
        expect(op.operationId, `${method} ${path} needs an operationId`).toBeTruthy();
        ids.push(op.operationId!);
        expect(JSON.stringify(op.responses), `${method} ${path} should document 401`).toContain("Unauthorized");
      }
    }
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("resolves every $ref", () => {
    const refs = collectRefs(spec);
    expect(refs.length).toBeGreaterThan(5);
    for (const ref of refs) {
      const target = ref.replace(/^#\//, "").split("/").reduce<unknown>((node, key) => (node as Record<string, unknown> | undefined)?.[key], spec);
      expect(target, `${ref} does not resolve`).toBeDefined();
    }
  });

  it("is OpenAPI 3.1, requires bearer auth by default, and points at the given server", () => {
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.security).toEqual([{ bearerAuth: [] }]);
    expect(spec.servers[0].url).toBe("https://api.example.test/api/v1");
  });

  it("matches the real report shape: ScanReport requires the always-present fields", () => {
    const required = (spec.components.schemas.ScanReport as unknown as { required: string[] }).required;
    // critical_paths is always present by contract (scanReport.ts), even when empty.
    expect(required).toEqual(expect.arrayContaining(["scan_id", "target_url", "status", "score", "findings", "critical_paths"]));
  });
});

// The strongest drift guard: validate what the code actually produces against
// the schema the spec publishes, so a renamed or retyped field fails here.
describe("OpenAPI ScanReport schema vs real output", () => {
  // The published refs are #/components/schemas/X; zod resolves $defs, so validate a $defs copy.
  const defs = JSON.parse(JSON.stringify(spec.components.schemas).replaceAll("#/components/schemas/", "#/$defs/"));
  const validator = z.fromJSONSchema({ $ref: "#/$defs/ScanReport", $defs: defs } as never);

  const scan = { id: "3f1c2a4e-1b7e-4a3c-9d57-0f6f3f5a1c11", owner: "o1", target_url: "https://shop.example/", status: "completed", created_at: "2026-10-01T00:00:00Z" };
  const findings: Finding[] = [
    { severity: "high", title: "No CSP", detail: "d", checkId: "headers.csp-absent", remediation: "Add one" },
    { severity: "low", title: "Old lib", detail: "d", checkId: "libs.jquery", cveIds: ["CVE-2020-1"], threatIntel: { knownExploited: true, kevCveIds: ["CVE-2020-1"], epss: 0.4, epssPercentile: 0.9 } },
    { severity: "info", title: "Untagged", detail: "d" },
  ];
  const result = { results: { findings }, summary: "ok", score: 80, created_at: "2026-10-01T00:05:00Z" };

  it("accepts a completed report with no previous scan", () => {
    const r = validator.safeParse(buildScanReport(scan, result, null));
    expect(r.success, r.success ? "" : JSON.stringify(r.error.issues.slice(0, 3))).toBe(true);
  });

  it("accepts a completed report compared against a previous scan", () => {
    const previous: Finding[] = [{ severity: "high", title: "No CSP", detail: "d", checkId: "headers.csp-absent" }, { severity: "low", title: "Gone", detail: "d", checkId: "dns.old" }];
    const report = buildScanReport(scan, result, previous);
    const r = validator.safeParse(report);
    expect(r.success, r.success ? "" : JSON.stringify(r.error.issues.slice(0, 3))).toBe(true);
    expect(report.fixed_findings?.length).toBe(1);
  });

  it("accepts the pending shape returned before a scan has results", () => {
    const r = validator.safeParse(pendingScanReport({ ...scan, status: "queued" }));
    expect(r.success, r.success ? "" : JSON.stringify(r.error.issues.slice(0, 3))).toBe(true);
  });

  it("rejects a report missing a required field (the validator is not vacuous)", () => {
    const { score: _score, ...withoutScore } = buildScanReport(scan, result, null);
    expect(validator.safeParse(withoutScore).success).toBe(false);
  });
});
