import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import type { CycloneDxBom } from "@/lib/sbomExport";
import type { DependencyInventory } from "@/lib/scanners/dependencyManifest";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

// Same chainable query-builder stub as export.test.ts, keyed by table.
function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: () => Promise.resolve(result),
  };
  return builder;
}

let supabaseTables: Record<string, unknown> = {};

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: {
    from: (table: string) => makeQueryBuilder(supabaseTables[table]),
  },
}));

import handler from "@/pages/api/v1/scans/[id]/sbom";

function call() {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query: { id: "scan-1" }, headers: { authorization: "Bearer test-token" } });
  return { req, res };
}

const INVENTORY: DependencyInventory = {
  schemaVersion: 1,
  files: [{ file: "package-lock.json", ecosystem: "npm", kind: "lockfile", graph: true }],
  packages: [
    { ecosystem: "npm", name: "web-frame", version: "4.1.0", direct: true, scope: "required", fileIndex: 0, dependsOn: [1] },
    { ecosystem: "npm", name: "deep-merge", version: "1.0.5", direct: false, scope: "required", fileIndex: 0, vulnIds: ["GHSA-test-0002"] },
  ],
  totalPackages: 2,
  truncated: false,
  vulnerabilityLookup: "completed",
  advisories: [{ id: "GHSA-test-0002", cveIds: ["CVE-2099-0002"], severity: "medium" }],
};

describe("GET /api/v1/scans/[id]/sbom", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset();
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    supabaseTables = { scans: { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } } };
  });

  it("rejects non-GET and unauthenticated requests", async () => {
    const post = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(post.req, post.res);
    expect(post.res._getStatusCode()).toBe(405);

    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 403 for someone else's scan", async () => {
    supabaseTables.scans = { data: { id: "scan-1", owner: "someone-else", target_url: "https://example.com" } };
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("builds the SBOM from the stored inventory, every package included", async () => {
    supabaseTables.scan_results = { data: { results: { findings: [], extended: { dependencyManifest: { status: "completed", inventory: INVENTORY } } } } };
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="example.com-sbom.cdx.json"');
    const bom = res._getJSONData() as CycloneDxBom;
    expect(bom.components.map((c) => c.purl)).toEqual(["pkg:npm/web-frame@4.1.0", "pkg:npm/deep-merge@1.0.5"]);
    expect(bom.dependencies).toContainEqual({ ref: "application", dependsOn: ["pkg:npm/web-frame@4.1.0"] });
    expect(bom.vulnerabilities?.[0]).toMatchObject({ id: "GHSA-test-0002", affects: [{ ref: "pkg:npm/deep-merge@1.0.5" }] });
  });

  it("uses an error-status scan's inventory too, without claiming no vulnerabilities", async () => {
    supabaseTables.scan_results = {
      data: { results: { findings: [], extended: { dependencyManifest: { status: "error", inventory: { ...INVENTORY, vulnerabilityLookup: "failed", advisories: [] } } } } },
    };
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as CycloneDxBom).vulnerabilities).toBeUndefined();
  });

  it("falls back to findings for scans stored before the inventory existed", async () => {
    supabaseTables.scan_results = {
      data: {
        results: {
          findings: [
            { checkId: "dependency-manifest.maven:org.example:demo-lib", severity: "medium", title: "Vulnerable dependency: org.example:demo-lib@1.0.0", detail: "", cveIds: ["CVE-2099-0003"] },
            { checkId: "tls.grade", severity: "low", title: "TLS", detail: "" },
          ],
          extended: { dependencyManifest: { status: "completed", findings: [] } },
        },
      },
    };
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    const bom = res._getJSONData() as CycloneDxBom;
    expect(bom.components.map((c) => c.purl)).toEqual(["pkg:maven/org.example/demo-lib@1.0.0"]);
    expect(bom.vulnerabilities?.[0].id).toBe("CVE-2099-0003");
  });

  it("returns 404 only when there's no dependency data at all", async () => {
    supabaseTables.scan_results = { data: { results: { findings: [{ checkId: "tls.grade", severity: "low", title: "TLS", detail: "" }] } } };
    const { req, res } = call();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);

    supabaseTables.scan_results = { data: null };
    const second = call();
    await handler(second.req, second.res);
    expect(second.res._getStatusCode()).toBe(404);
  });
});
