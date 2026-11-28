// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fakeSupabase, type FakeQuery, type FakeResult } from "./fakeSupabase";

const { viewMock } = vi.hoisted(() => ({ viewMock: vi.fn() }));
vi.mock("../findingsView", () => ({ loadFindingsView: viewMock }));

import { loadEvidenceFacts, summariseDevices } from "./evidence";

const NOW = new Date("2026-11-27T12:00:00Z");

describe("summariseDevices", () => {
  it("is null with no active device", () => {
    expect(summariseDevices([], NOW)).toBeNull();
    expect(summariseDevices([{ revoked_at: "2026-11-01", last_seen_at: null, patch_status: "passes", last_match: null }], NOW)).toBeNull();
  });

  it("counts reporting devices by status, leaving out stale and silent ones", () => {
    const d = summariseDevices(
      [
        { revoked_at: null, last_seen_at: "2026-11-26T00:00:00Z", patch_status: "passes", last_match: { osEol: { state: "unsupported" } } },
        { revoked_at: null, last_seen_at: "2026-11-27T00:00:00Z", patch_status: "fails", last_match: null },
        { revoked_at: null, last_seen_at: "2026-11-25T00:00:00Z", patch_status: "at_risk", last_match: { osEol: null } },
        { revoked_at: null, last_seen_at: "2026-11-25T00:00:00Z", patch_status: "unknown", last_match: null },
        { revoked_at: null, last_seen_at: "2025-01-01T00:00:00Z", patch_status: "passes", last_match: null },
        { revoked_at: null, last_seen_at: null, patch_status: "never_reported", last_match: null },
      ],
      NOW,
    );
    expect(d).toEqual({ total: 6, reporting: 4, passes: 1, atRisk: 1, fails: 1, unsupportedOs: 1, lastSeenAt: "2026-11-27T00:00:00Z" });
  });
});

describe("loadEvidenceFacts", () => {
  let tables: Record<string, FakeResult>;
  const resolve = (q: FakeQuery) => tables[q.table] ?? { data: [] };

  beforeEach(() => {
    viewMock.mockReset().mockResolvedValue({
      ok: true,
      data: {
        rows: [
          { host: "acme.co.uk", checkId: "dns.dmarc-missing", title: "DMARC missing", knownExploited: false, triage: null },
          { host: "acme.co.uk", checkId: "headers.csp", title: "No CSP", knownExploited: false, triage: { state: "false_positive" } },
        ],
      },
    });
    tables = {
      scans: {
        data: [
          { id: "s3", target_url: "https://acme.co.uk/", created_at: "2026-11-20T00:00:00Z" },
          { id: "s2", target_url: "https://acme.co.uk", created_at: "2026-11-01T00:00:00Z" },
          { id: "s1", target_url: "https://shop.acme.co.uk", created_at: "2026-10-01T00:00:00Z" },
          { id: "s0", target_url: "not a url", created_at: "2026-09-01T00:00:00Z" },
          { id: "s9", target_url: "https://lost.example", created_at: "2026-08-01T00:00:00Z" },
        ],
      },
      scan_results: {
        data: [
          { scan_id: "s3", score: 82, created_at: "2026-11-20T00:00:00Z", tls: "checked", dns: "checked", ports: "error", hibp: null },
          { scan_id: "s1", score: null, created_at: "2026-10-01T00:00:00Z", tls: "checked", dns: "error", ports: "checked", hibp: "checked" },
        ],
      },
      m365_tenants: { data: { last_checked_at: "2026-11-21T00:00:00Z" } },
      workspace_connections: { data: null },
      ce_self_assessment: { data: [{ question_key: "user-access.mfa", answer: "yes", updated_at: "2026-11-10T00:00:00Z" }] },
      agent_devices: { data: [{ revoked_at: null, last_seen_at: "2026-11-26T00:00:00Z", patch_status: "passes", last_match: null }] },
      trust_documents: { data: [{ kind: "policy", title: "Infosec policy", uploaded_at: "2026-09-01T00:00:00Z", target_host: "acme.co.uk" }] },
      security_profiles: { data: [{ target_host: "acme.co.uk" }] },
    };
  });

  it("gathers every source, newest site first, using only each host's latest scan", async () => {
    const { client, calls } = fakeSupabase(resolve);
    const f = await loadEvidenceFacts(client, "owner-1", NOW);
    expect(f.findings).toEqual([{ host: "acme.co.uk", checkId: "dns.dmarc-missing", title: "DMARC missing", knownExploited: false }]);
    expect(f.sites).toEqual([
      { host: "acme.co.uk", lastScanAt: "2026-11-20T00:00:00Z", score: 82, evaluated: { tls: true, dns: true, ports: false, hibp: false } },
      { host: "shop.acme.co.uk", lastScanAt: "2026-10-01T00:00:00Z", score: null, evaluated: { tls: true, dns: false, ports: true, hibp: true } },
    ]);
    expect(f.m365CheckedAt).toBe("2026-11-21T00:00:00Z");
    expect(f.workspaceCheckedAt).toBeNull();
    expect(f.declared).toEqual([{ questionKey: "user-access.mfa", answer: "yes", updatedAt: "2026-11-10T00:00:00Z" }]);
    expect(f.devices?.reporting).toBe(1);
    expect(f.documents).toEqual([{ kind: "policy", title: "Infosec policy", uploadedAt: "2026-09-01T00:00:00Z", host: "acme.co.uk" }]);
    expect(f.profileHosts).toEqual(["acme.co.uk"]);
    // Every read is scoped to the caller.
    for (const q of calls.filter((c) => c.table !== "scan_results")) expect(q.filters).toContainEqual(["eq", "owner", "owner-1"]);
    expect(calls.find((c) => c.table === "scan_results")?.filters).toContainEqual(["in", "scan_id", ["s3", "s1", "s9"]]);
  });

  it("leaves out every source that can't be read, never treating a failure as clean", async () => {
    viewMock.mockRejectedValue(new Error("boom"));
    const err = { data: null, error: { message: "relation does not exist", code: "42P01" } };
    for (const t of Object.keys(tables)) tables[t] = err;
    const { client } = fakeSupabase(resolve);
    const f = await loadEvidenceFacts(client, "owner-1", NOW);
    expect(f).toEqual({ findings: [], sites: [], m365CheckedAt: null, workspaceCheckedAt: null, declared: [], devices: null, documents: [], profileHosts: [] });
  });

  it("drops a site whose results can't be read, and a findings view that says not ok", async () => {
    viewMock.mockResolvedValue({ ok: false, error: "x" });
    tables.scan_results = { data: null, error: { message: "x" } };
    const { client } = fakeSupabase(resolve);
    const f = await loadEvidenceFacts(client, "owner-1", NOW);
    expect(f.sites).toEqual([]);
    expect(f.findings).toEqual([]);
  });

  it("skips the results read with no completed scans", async () => {
    tables.scans = { data: [] };
    const { client, calls } = fakeSupabase(resolve);
    await loadEvidenceFacts(client, "owner-1");
    expect(calls.some((c) => c.table === "scan_results")).toBe(false);
  });
});
