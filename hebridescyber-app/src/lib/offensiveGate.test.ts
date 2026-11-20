import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { EngagementScopeFacts } from "./exploitability/scope/scopeGuard";

const m = vi.hoisted(() => ({ tier: vi.fn(), auth: vi.fn(), facts: vi.fn(), audit: vi.fn() }));
vi.mock("./planAccess", () => ({ hasTierAAccess: m.tier }));
vi.mock("./offensiveAuthorization", async (original) => ({ ...(await original<typeof import("./offensiveAuthorization")>()), loadCurrentOffensiveAuthorization: m.auth }));
vi.mock("./exploitability/load", () => ({ loadEngagementScopeFacts: m.facts }));
vi.mock("./audit", () => ({ logAuditEvent: m.audit }));

import { auditOffensiveGate, describeRefusal, evaluateOffensiveGate, requireEngagementForOffensive, type OffensiveGateDecision } from "./offensiveGate";

const admin = {} as SupabaseClient;
const OWNER = "owner-1";
const URL = "https://shop.example.com/login";
const HOST = "shop.example.com";
const ENG = "eng-1";
const NOW = new Date("2026-11-06T12:00:00Z");

const engagement = (over: Partial<NonNullable<EngagementScopeFacts["engagement"]>> = {}): NonNullable<EngagementScopeFacts["engagement"]> => ({
  id: ENG,
  owner: OWNER,
  state: "in_window",
  windowStart: "2026-11-06T00:00:00Z",
  windowEnd: "2026-11-07T00:00:00Z",
  expiresAt: "2026-11-08T00:00:00Z",
  testingWindows: [],
  scanProfile: "offensive",
  ...over,
});
const facts = (over: Partial<EngagementScopeFacts> = {}): EngagementScopeFacts => ({
  lookupFailed: false,
  engagement: engagement(),
  scopeHosts: [{ host: HOST, included: true }],
  domainVerified: true,
  authorization: { revoked_at: null, expires_at: null, engagement_id: ENG },
  ...over,
});

const gate = (opts: { requireEngagement?: boolean } = {}) => evaluateOffensiveGate(admin, OWNER, URL, NOW, opts);

beforeEach(() => {
  for (const fn of Object.values(m)) fn.mockReset();
  m.tier.mockResolvedValue(true);
  m.auth.mockResolvedValue({ engagementId: ENG });
  m.facts.mockResolvedValue(facts());
});

describe("evaluateOffensiveGate", () => {
  it("allows an engagement-linked run inside the signed scope and window, naming the engagement", async () => {
    expect(await gate()).toEqual({ allowed: true, engagementId: ENG });
    expect(m.facts).toHaveBeenCalledWith(admin, ENG, HOST);
    expect(m.auth).toHaveBeenCalledWith(admin, OWNER, URL, NOW);
  });

  it("refuses an owner not on Tier A, even with an authorisation, and a failed plan read", async () => {
    m.tier.mockResolvedValue(false);
    expect(await gate()).toEqual({ allowed: false, reason: "not_tier_a", engagementId: ENG });
    m.tier.mockRejectedValue(new Error("db down"));
    expect((await gate()).allowed).toBe(false);
  });

  it("refuses with no current authorisation", async () => {
    m.auth.mockResolvedValue(null);
    expect(await gate()).toEqual({ allowed: false, reason: "no_authorization", engagementId: null });
    expect(m.facts).not.toHaveBeenCalled();
  });

  it("keeps a legacy unlinked authorisation working unless an engagement is required", async () => {
    m.auth.mockResolvedValue({ engagementId: null });
    expect(await gate({ requireEngagement: false })).toEqual({ allowed: true, engagementId: null });
    expect(await gate({ requireEngagement: true })).toEqual({ allowed: false, reason: "engagement_required", engagementId: null });
    expect(m.facts).not.toHaveBeenCalled();
  });

  it.each([
    ["engagement_not_in_window", facts({ engagement: engagement({ windowEnd: "2026-11-06T06:00:00Z", expiresAt: "2026-11-06T06:00:00Z" }) })],
    ["engagement_expired", facts({ engagement: engagement({ expiresAt: NOW.toISOString() }) })],
    ["outside_testing_window", facts({ engagement: engagement({ testingWindows: [{ startsAt: "2026-11-06T13:00:00Z", endsAt: "2026-11-06T17:00:00Z" }] }) })],
    ["engagement_state_disallows", facts({ engagement: engagement({ state: "aborted" }) })],
    ["engagement_state_disallows", facts({ engagement: engagement({ state: "reported" }) })],
    ["host_not_in_scope", facts({ scopeHosts: [{ host: "www.example.com", included: true }] })],
    ["host_explicitly_excluded", facts({ scopeHosts: [{ host: HOST, included: true }, { host: HOST, included: false }] })],
    ["domain_not_verified", facts({ domainVerified: false })],
    ["authorization_missing", facts({ authorization: { revoked_at: null, expires_at: null, engagement_id: "another-engagement" } })],
    ["lookup_failed", facts({ lookupFailed: true })],
    ["engagement_not_found", facts({ engagement: null })],
  ] as const)("refuses an engagement-linked run outside scope: %s", async (scopeRefusal, scopeFacts) => {
    m.facts.mockResolvedValue(scopeFacts);
    expect(await gate()).toEqual({ allowed: false, reason: "out_of_engagement_scope", engagementId: ENG, scopeRefusal });
  });

  it("refuses an engagement that belongs to another account", async () => {
    m.facts.mockResolvedValue(facts({ engagement: engagement({ owner: "someone-else" }) }));
    expect(await gate()).toEqual({ allowed: false, reason: "out_of_engagement_scope", engagementId: ENG, scopeRefusal: "engagement_not_found" });
  });

  it("refuses when the engagement only allows a non-offensive profile", async () => {
    for (const scanProfile of ["safe", "exposure"] as const) {
      m.facts.mockResolvedValue(facts({ engagement: engagement({ scanProfile }) }));
      expect(await gate()).toEqual({ allowed: false, reason: "engagement_profile_disallows", engagementId: ENG });
    }
  });

  it("checks scope even when engagements aren't required: a link always binds", async () => {
    m.facts.mockResolvedValue(facts({ scopeHosts: [] }));
    expect((await gate({ requireEngagement: false })).allowed).toBe(false);
  });
});

describe("requireEngagementForOffensive", () => {
  it("is on only for exactly 1", () => {
    expect(requireEngagementForOffensive({ OFFENSIVE_REQUIRE_ENGAGEMENT: "1" })).toBe(true);
    for (const v of [undefined, "", "0", "true", "yes"]) expect(requireEngagementForOffensive({ OFFENSIVE_REQUIRE_ENGAGEMENT: v })).toBe(false);
  });
});

describe("auditOffensiveGate", () => {
  const job = { id: "job-1", owner: OWNER, target_url: URL };
  const actions = () => m.audit.mock.calls.map((c) => (c[1] as { action: string }).action);

  it("records a pass with the engagement it ran under", async () => {
    await auditOffensiveGate(admin, job, { allowed: true, engagementId: ENG }, "offensive");
    expect(m.audit.mock.calls[0][1]).toEqual({
      actorId: OWNER,
      action: "offensive_scan.ran",
      resourceType: "scan_job",
      resourceId: "job-1",
      metadata: { target_url: URL, profile: "offensive", engagement_id: ENG },
    });
  });

  it("records a scope refusal on the job and on the engagement", async () => {
    const decision: OffensiveGateDecision = { allowed: false, reason: "out_of_engagement_scope", engagementId: ENG, scopeRefusal: "outside_testing_window" };
    await auditOffensiveGate(admin, job, decision, "ai-pentest");
    expect(actions()).toEqual(["offensive_scan.refused", "engagement_scope.refused"]);
    expect(m.audit.mock.calls[0][1]).toMatchObject({ metadata: { code: "out_of_engagement_scope", scope_refusal: "outside_testing_window", engagement_id: ENG, profile: "ai-pentest" } });
    expect(m.audit.mock.calls[1][1]).toEqual({
      actorId: OWNER,
      action: "engagement_scope.refused",
      resourceType: "engagement",
      resourceId: ENG,
      metadata: { host: HOST, reason: "outside_testing_window", scan_job_id: "job-1" },
    });
  });

  it("keeps the old wording for a legacy refusal and writes nothing on an engagement", async () => {
    await auditOffensiveGate(admin, job, { allowed: false, reason: "no_authorization", engagementId: null }, "offensive");
    expect(actions()).toEqual(["offensive_scan.refused"]);
    expect(m.audit.mock.calls[0][1]).toMatchObject({ metadata: { reason: "no current offensive-scan authorization for this target" } });
  });

  it("doesn't put a Tier A refusal on the engagement's record", async () => {
    await auditOffensiveGate(admin, job, { allowed: false, reason: "not_tier_a", engagementId: ENG }, "offensive");
    expect(actions()).toEqual(["offensive_scan.refused"]);
  });
});

describe("describeRefusal", () => {
  it("adds the scope reason when there is one", () => {
    expect(describeRefusal({ allowed: false, reason: "out_of_engagement_scope", engagementId: ENG, scopeRefusal: "engagement_expired" })).toBe("target is outside the engagement's signed scope or window (engagement_expired)");
    expect(describeRefusal({ allowed: false, reason: "not_tier_a", engagementId: null })).toBe("owner is not on Tier A");
  });
});
