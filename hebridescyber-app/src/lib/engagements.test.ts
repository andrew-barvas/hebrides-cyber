import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { verified, audit } = vi.hoisted(() => ({ verified: vi.fn(), audit: vi.fn() }));
vi.mock("./ownership", () => ({ isDomainVerified: verified }));
vi.mock("./audit", () => ({ logAuditEvent: audit }));

import {
  accountExists,
  abortEngagement,
  applyScopeChanges,
  checkAuthorizationLink,
  checkTestingWindows,
  isEditableState,
  loadContacts,
  loadEngagement,
  loadIncludedHostFacts,
  loadTestingWindows,
  replaceContacts,
  replaceTestingWindows,
  linkedAuthorizationExpiry,
  ADMIN_LIST_LIMIT,
  listAllEngagements,
  listOwnerEngagements,
  loadEngagementView,
  updateEngagement,
} from "./engagements";

type Reply = { data?: unknown; error?: { code?: string; message?: string } | null };

/** A chainable stand-in: each awaited query takes the next reply queued for its table. */
function fakeAdmin(replies: Record<string, Reply[]>, rpc?: Reply) {
  const writes: { table: string; op: string; row?: unknown; filters: unknown[][] }[] = [];
  const reads: { table: string; filters: unknown[][] }[] = [];
  const admin = {
    rpc: vi.fn(async () => rpc ?? { data: null, error: null }),
    from(table: string) {
      const filters: unknown[][] = [];
      reads.push({ table, filters });
      let write: (typeof writes)[number] | undefined;
      const next = () => (replies[table] ?? []).shift() ?? { data: null, error: null };
      const builder: Record<string, unknown> = {
        select: () => builder,
        eq: (...args: unknown[]) => (filters.push(args), builder),
        is: (...args: unknown[]) => (filters.push(args), builder),
        not: (...args: unknown[]) => (filters.push(["not", ...args]), builder),
        order: () => builder,
        limit: () => builder,
        maybeSingle: async () => next(),
        then: (resolve: (r: Reply) => unknown) => resolve(next()),
        update: (row: unknown) => ((write = { table, op: "update", row, filters }), writes.push(write), builder),
        insert: (row: unknown) => ((write = { table, op: "insert", row, filters }), writes.push(write), builder),
      };
      return builder;
    },
  };
  return { admin: admin as unknown as SupabaseClient, writes, rpc: admin.rpc, filters: () => reads.flatMap((r) => r.filters) };
}

const ENGAGEMENT = { id: "eng-1", owner: "owner-1" };
const NOW = new Date("2026-11-06T12:00:00Z");

beforeEach(() => {
  verified.mockReset().mockResolvedValue(true);
  audit.mockReset();
});

describe("loadEngagement", () => {
  it("separates missing, unavailable and failed", async () => {
    expect(await loadEngagement(fakeAdmin({ engagements: [{ data: null }] }).admin, "x")).toEqual({ status: "not_found" });
    expect(await loadEngagement(fakeAdmin({ engagements: [{ error: { code: "42P01" } }] }).admin, "x")).toEqual({ status: "unavailable" });
    expect((await loadEngagement(fakeAdmin({ engagements: [{ error: { code: "XX000" } }] }).admin, "x")).status).toBe("error");
    expect(await loadEngagement(fakeAdmin({ engagements: [{ data: { id: "x" } }] }).admin, "x")).toEqual({ status: "ok", data: { id: "x" } });
  });
});

describe("updateEngagement", () => {
  it("only writes from the state the decision was made in", async () => {
    const { admin, writes } = fakeAdmin({ engagements: [{ data: null }] });
    expect(await updateEngagement(admin, "eng-1", "scoped", { state: "authorised" })).toEqual({ status: "ok", data: null });
    expect(writes[0].filters).toContainEqual(["state", "scoped"]);
  });
});

describe("loadIncludedHostFacts", () => {
  const scope = { data: [{ host: "a.test" }, { host: "b.test" }] };

  it("reports each included host's verification and linked, current authorisation", async () => {
    verified.mockImplementation(async (_a, _o, url: string) => url.includes("a.test"));
    const auths = { data: [{ target_host: "a.test", revoked_at: null, expires_at: null }, { target_host: "b.test", revoked_at: null, expires_at: "2026-01-01T00:00:00Z" }] };
    const { admin } = fakeAdmin({ engagement_scope_hosts: [scope], offensive_scan_authorizations: [auths] });
    expect(await loadIncludedHostFacts(admin, ENGAGEMENT, NOW)).toEqual({
      status: "ok",
      data: [
        { host: "a.test", domainVerified: true, authorizationLinkedAndCurrent: true, authorizationExpiresAt: null },
        { host: "b.test", domainVerified: false, authorizationLinkedAndCurrent: false, authorizationExpiresAt: null },
      ],
    });
  });

  it("reports when each host's current linked authorisation ends, taking the latest", async () => {
    const auths = {
      data: [
        { target_host: "a.test", revoked_at: null, expires_at: "2026-11-20T00:00:00Z" },
        { target_host: "a.test", revoked_at: null, expires_at: "2026-11-30T00:00:00Z" },
        { target_host: "b.test", revoked_at: null, expires_at: "2026-11-01T00:00:00Z" },
      ],
    };
    const { admin } = fakeAdmin({ engagement_scope_hosts: [scope], offensive_scan_authorizations: [auths] });
    const result = await loadIncludedHostFacts(admin, ENGAGEMENT, NOW);
    expect(result.status === "ok" && result.data.map((h) => h.authorizationExpiresAt)).toEqual(["2026-11-30T00:00:00Z", null]);
  });

  it("is a failure, never empty facts, on a failed read", async () => {
    expect((await loadIncludedHostFacts(fakeAdmin({ engagement_scope_hosts: [{ error: { code: "XX000" } }] }).admin, ENGAGEMENT, NOW)).status).toBe("error");
    expect((await loadIncludedHostFacts(fakeAdmin({ engagement_scope_hosts: [scope], offensive_scan_authorizations: [{ error: { code: "XX000" } }] }).admin, ENGAGEMENT, NOW)).status).toBe("error");
  });
});

describe("applyScopeChanges", () => {
  const actions = () => audit.mock.calls.map((c) => (c[1] as { action: string }).action);

  it("normalises the host, stores who added it, and audits", async () => {
    const { admin, writes } = fakeAdmin({});
    const result = await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [{ host: " A.Example.COM ", included: true, trustGroup: "shop" }], remove: [] });
    expect(result).toEqual({ status: "ok", data: { added: [{ host: "a.example.com", included: true }], removed: [], refused: [] } });
    expect(writes.find((w) => w.op === "insert")?.row).toEqual({ engagement_id: "eng-1", owner: "owner-1", host: "a.example.com", included: true, trust_group: "shop", added_by: "admin-1" });
    expect(actions()).toEqual(["engagement_scope.host_added"]);
  });

  it("refuses an included host without a verified domain, per host, and keeps going", async () => {
    verified.mockImplementation(async (_a, _o, url: string) => !url.includes("bad.test"));
    const { admin, writes } = fakeAdmin({});
    const result = await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [{ host: "bad.test", included: true }, { host: "good.test", included: true }], remove: [] });
    expect(result).toEqual({ status: "ok", data: { added: [{ host: "good.test", included: true }], removed: [], refused: [{ host: "bad.test", reason: "domain_not_verified" }] } });
    expect(writes.filter((w) => w.op === "insert")).toHaveLength(1);
    expect(actions()).toEqual(["engagement_scope.refused", "engagement_scope.host_added"]);
  });

  it("doesn't need verification to exclude a host", async () => {
    verified.mockResolvedValue(false);
    const result = await applyScopeChanges(fakeAdmin({}).admin, ENGAGEMENT, "admin-1", { add: [{ host: "out.test", included: false }], remove: [] });
    expect(result).toMatchObject({ data: { added: [{ host: "out.test", included: false }], refused: [] } });
    expect(verified).not.toHaveBeenCalled();
  });

  it.each(["*.example.com", "https://example.com", "example.com:8443", "example.com."])("refuses %s, which isn't one bare host", async (host) => {
    const { admin, writes } = fakeAdmin({});
    const result = await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [{ host, included: true }], remove: [] });
    expect(result).toMatchObject({ data: { refused: [{ host, reason: "invalid_host" }] } });
    expect(writes).toHaveLength(0);
  });

  it("removes softly, and refuses a host that isn't listed", async () => {
    const { admin, writes } = fakeAdmin({ engagement_scope_hosts: [{ data: [{ host: "a.test" }] }, { data: [] }] });
    const result = await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [], remove: ["a.test", "gone.test"] });
    expect(result).toEqual({ status: "ok", data: { added: [], removed: ["a.test"], refused: [{ host: "gone.test", reason: "not_listed" }] } });
    expect(writes[0]).toMatchObject({ op: "update", row: { removed_at: expect.any(String) } });
    expect(actions()).toEqual(["engagement_scope.host_removed", "engagement_scope.refused"]);
  });

  it("replaces a host's row when its in/out flag changes, so there's one active row", async () => {
    const { admin, writes } = fakeAdmin({});
    await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [{ host: "a.test", included: false }], remove: [] });
    expect(writes.map((w) => w.op)).toEqual(["update", "insert"]);
  });

  it("is a failure on a failed write, without claiming the change", async () => {
    const { admin } = fakeAdmin({ engagement_scope_hosts: [{ data: [] }, { error: { code: "XX000" } }] });
    expect((await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [{ host: "a.test", included: true }], remove: [] })).status).toBe("error");
    expect(actions()).toEqual([]);
  });
});

describe("checkAuthorizationLink", () => {
  const row = (state: string, owner = "owner-1") => ({ data: { id: "eng-1", owner, state, expires_at: "2026-12-31T00:00:00Z" } });

  it("allows the owner's listed host before the engagement is authorised, passing on the engagement's expiry", async () => {
    for (const state of ["booked", "scoped"]) {
      const { admin } = fakeAdmin({ engagements: [row(state)], engagement_scope_hosts: [{ data: { host: "a.test" } }] });
      expect(await checkAuthorizationLink(admin, "owner-1", "eng-1", "a.test")).toEqual({ status: "ok", data: { ok: true, engagementExpiresAt: "2026-12-31T00:00:00Z" } });
    }
  });

  it("looks like nothing is there for someone else's engagement", async () => {
    const { admin } = fakeAdmin({ engagements: [row("scoped", "someone-else")] });
    expect(await checkAuthorizationLink(admin, "owner-1", "eng-1", "a.test")).toEqual({ status: "not_found" });
  });

  it.each(["authorised", "in_window", "reported", "closed", "aborted"])("refuses a new link in state %s", async (state) => {
    const { admin } = fakeAdmin({ engagements: [row(state)] });
    expect(await checkAuthorizationLink(admin, "owner-1", "eng-1", "a.test")).toEqual({ status: "ok", data: { ok: false, reason: "state_disallows" } });
  });

  it("refuses a host not on the list, and fails on a failed read", async () => {
    expect(await checkAuthorizationLink(fakeAdmin({ engagements: [row("scoped")], engagement_scope_hosts: [{ data: null }] }).admin, "owner-1", "eng-1", "a.test")).toEqual({ status: "ok", data: { ok: false, reason: "host_not_in_scope" } });
    expect((await checkAuthorizationLink(fakeAdmin({ engagements: [row("scoped")], engagement_scope_hosts: [{ error: { code: "XX000" } }] }).admin, "owner-1", "eng-1", "a.test")).status).toBe("error");
  });
});

describe("abortEngagement", () => {
  it("maps the function's result", async () => {
    const { admin, rpc } = fakeAdmin({}, { data: { outcome: "aborted", from: "in_window", revoked_hosts: ["a.test"], simulations_withdrawn: 2 } });
    expect(await abortEngagement(admin, "eng-1", "stop")).toEqual({ status: "ok", data: { outcome: "aborted", from: "in_window", revokedHosts: ["a.test"], simulationsWithdrawn: 2 } });
    expect(rpc).toHaveBeenCalledWith("abort_engagement", { p_engagement_id: "eng-1", p_reason: "stop" });
  });

  it("passes closed and not_found through", async () => {
    expect(await abortEngagement(fakeAdmin({}, { data: { outcome: "closed" } }).admin, "e", null)).toEqual({ status: "ok", data: { outcome: "closed" } });
    expect(await abortEngagement(fakeAdmin({}, { data: { outcome: "not_found" } }).admin, "e", null)).toEqual({ status: "ok", data: { outcome: "not_found" } });
  });

  it("is unavailable before the migration, and a failure on anything else", async () => {
    expect(await abortEngagement(fakeAdmin({}, { error: { code: "PGRST202" } }).admin, "e", null)).toEqual({ status: "unavailable" });
    expect((await abortEngagement(fakeAdmin({}, { error: { code: "XX000" } }).admin, "e", null)).status).toBe("error");
  });
});

describe("isEditableState", () => {
  it("allows edits only before the engagement is authorised", () => {
    expect(isEditableState("booked")).toBe(true);
    expect(isEditableState("scoped")).toBe(true);
    for (const s of ["authorised", "in_window", "reported", "closed", "aborted"] as const) expect(isEditableState(s)).toBe(false);
  });
});

describe("loadContacts and loadTestingWindows", () => {
  it("read active rows only, and report a failed read as a failure", async () => {
    const { admin } = fakeAdmin({ engagement_contacts: [{ data: [{ id: "c1", kind: "emergency" }] }], engagement_testing_windows: [{ data: null }] });
    expect(await loadContacts(admin, "eng-1")).toEqual({ status: "ok", data: [{ id: "c1", kind: "emergency" }] });
    expect(await loadTestingWindows(admin, "eng-1")).toEqual({ status: "ok", data: [] });
    expect((await loadContacts(fakeAdmin({ engagement_contacts: [{ error: { code: "XX000" } }] }).admin, "eng-1")).status).toBe("error");
    expect(await loadTestingWindows(fakeAdmin({ engagement_testing_windows: [{ error: { code: "42P01" } }] }).admin, "eng-1")).toEqual({ status: "unavailable" });
  });
});

describe("replaceContacts", () => {
  it("inserts the new list first, then marks every other active row removed", async () => {
    const { admin, writes } = fakeAdmin({ engagement_contacts: [{ data: [{ id: "n1" }, { id: "n2" }] }, { data: null }] });
    const result = await replaceContacts(admin, ENGAGEMENT, "admin-1", [
      { kind: "emergency", name: "On call", phone: "+44 1" },
      { kind: "authoriser", name: "Boss", role: "CEO", email: "b@a.test" },
    ]);
    expect(result).toEqual({ status: "ok", data: [{ id: "n1" }, { id: "n2" }] });
    expect(writes.map((w) => w.op)).toEqual(["insert", "update"]);
    expect(writes[0].row).toEqual([
      { kind: "emergency", name: "On call", role: null, email: null, phone: "+44 1", engagement_id: "eng-1", owner: "owner-1", added_by: "admin-1" },
      { kind: "authoriser", name: "Boss", role: "CEO", email: "b@a.test", phone: null, engagement_id: "eng-1", owner: "owner-1", added_by: "admin-1" },
    ]);
    expect(writes[1].row).toEqual({ removed_at: expect.any(String) });
    expect(writes[1].filters).toContainEqual(["not", "id", "in", "(n1,n2)"]);
    expect(writes[1].filters).toContainEqual(["engagement_id", "eng-1"]);
  });

  it("leaves the old list in place when the insert fails", async () => {
    const { admin, writes } = fakeAdmin({ engagement_contacts: [{ error: { code: "23514" } }] });
    expect((await replaceContacts(admin, ENGAGEMENT, "admin-1", [{ kind: "technical", name: "X", email: "x@a.test" }])).status).toBe("error");
    expect(writes.map((w) => w.op)).toEqual(["insert"]);
  });

  it("an empty list removes every active row", async () => {
    const { admin, writes } = fakeAdmin({ engagement_contacts: [{ data: null }] });
    expect(await replaceContacts(admin, ENGAGEMENT, "admin-1", [])).toEqual({ status: "ok", data: [] });
    expect(writes.map((w) => w.op)).toEqual(["update"]);
    expect(writes[0].filters.some((f) => f[0] === "not")).toBe(false);
  });

  it("reports a failed removal", async () => {
    const { admin } = fakeAdmin({ engagement_contacts: [{ data: [{ id: "n1" }] }, { error: { code: "XX000" } }] });
    expect((await replaceContacts(admin, ENGAGEMENT, "admin-1", [{ kind: "technical", name: "X", email: "x@a.test" }])).status).toBe("error");
  });
});

describe("replaceTestingWindows", () => {
  it("stores each slot against the engagement", async () => {
    const { admin, writes } = fakeAdmin({ engagement_testing_windows: [{ data: [{ id: "w1" }] }, { data: null }] });
    await replaceTestingWindows(admin, ENGAGEMENT, "admin-1", [{ startsAt: "2026-11-02T09:00:00Z", endsAt: "2026-11-02T17:00:00Z" }]);
    expect(writes[0].row).toEqual([{ starts_at: "2026-11-02T09:00:00Z", ends_at: "2026-11-02T17:00:00Z", engagement_id: "eng-1", owner: "owner-1", added_by: "admin-1" }]);
  });
});

describe("checkTestingWindows", () => {
  const outer = { window_start: "2026-11-01T00:00:00Z", window_end: "2026-11-30T00:00:00Z" };
  it("accepts slots inside the overall window, including its edges, and no slots at all", () => {
    expect(checkTestingWindows(outer, [])).toBeNull();
    expect(checkTestingWindows({ window_start: null, window_end: null }, [])).toBeNull();
    expect(checkTestingWindows(outer, [{ startsAt: "2026-11-01T00:00:00Z", endsAt: "2026-11-30T00:00:00Z" }])).toBeNull();
  });
  it("names the first slot that is backwards, outside, or has no overall window to sit in", () => {
    expect(checkTestingWindows(outer, [{ startsAt: "2026-11-02T09:00:00Z", endsAt: "2026-11-02T17:00:00Z" }, { startsAt: "2026-11-29T23:00:00Z", endsAt: "2026-11-30T01:00:00Z" }])).toEqual({ problem: "outside_engagement_window", index: 1 });
    expect(checkTestingWindows(outer, [{ startsAt: "2026-11-02T17:00:00Z", endsAt: "2026-11-02T17:00:00Z" }])).toEqual({ problem: "end_before_start", index: 0 });
    expect(checkTestingWindows(outer, [{ startsAt: "bad", endsAt: "2026-11-02T17:00:00Z" }])).toEqual({ problem: "end_before_start", index: 0 });
    expect(checkTestingWindows({ window_start: "2026-11-01T00:00:00Z", window_end: null }, [{ startsAt: "2026-11-02T09:00:00Z", endsAt: "2026-11-02T17:00:00Z" }])).toEqual({ problem: "window_not_set" });
  });
});

describe("linkedAuthorizationExpiry", () => {
  const ENG_EXPIRY = "2026-12-31T00:00:00Z";
  it("never outlasts the engagement, and takes its expiry when none was asked for", () => {
    expect(linkedAuthorizationExpiry(undefined, ENG_EXPIRY)).toBe(ENG_EXPIRY);
    expect(linkedAuthorizationExpiry(null, ENG_EXPIRY)).toBe(ENG_EXPIRY);
    expect(linkedAuthorizationExpiry("2027-06-01T00:00:00Z", ENG_EXPIRY)).toBe(ENG_EXPIRY);
    expect(linkedAuthorizationExpiry("2026-12-01T00:00:00Z", ENG_EXPIRY)).toBe("2026-12-01T00:00:00Z");
  });
  it("leaves the request alone when the engagement has no expiry", () => {
    expect(linkedAuthorizationExpiry("2026-12-01T00:00:00Z", null)).toBe("2026-12-01T00:00:00Z");
    expect(linkedAuthorizationExpiry(undefined, null)).toBeNull();
  });
});

describe("listOwnerEngagements", () => {
  it("reads only the caller's rows", async () => {
    const { admin } = fakeAdmin({ engagements: [{ data: [{ id: "eng-1" }] }] });
    expect(await listOwnerEngagements(admin, "owner-1")).toEqual({ status: "ok", data: [{ id: "eng-1" }] });
    expect((await listOwnerEngagements(fakeAdmin({ engagements: [{ error: { code: "XX000" } }] }).admin, "owner-1")).status).toBe("error");
  });
});

describe("listAllEngagements", () => {
  it("reads every account's rows unfiltered, or one account's when given", async () => {
    const all = fakeAdmin({ engagements: [{ data: [{ id: "eng-1", owner: "owner-1" }, { id: "eng-2", owner: "owner-2" }] }] });
    expect(await listAllEngagements(all.admin, null)).toEqual({ status: "ok", data: { engagements: [{ id: "eng-1", owner: "owner-1" }, { id: "eng-2", owner: "owner-2" }], truncated: false } });
    expect(all.filters()).toEqual([]);

    const one = fakeAdmin({ engagements: [{ data: null }] });
    expect(await listAllEngagements(one.admin, "owner-1")).toEqual({ status: "ok", data: { engagements: [], truncated: false } });
    expect(one.filters()).toEqual([["owner", "owner-1"]]);
  });

  it("returns at most the limit and says when older ones were left out", async () => {
    const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `eng-${i}` }));
    const full = await listAllEngagements(fakeAdmin({ engagements: [{ data: rows(ADMIN_LIST_LIMIT) }] }).admin, null);
    expect(full.status === "ok" && [full.data.engagements.length, full.data.truncated]).toEqual([ADMIN_LIST_LIMIT, false]);
    const over = await listAllEngagements(fakeAdmin({ engagements: [{ data: rows(ADMIN_LIST_LIMIT + 1) }] }).admin, null);
    expect(over.status === "ok" && [over.data.engagements.length, over.data.truncated]).toEqual([ADMIN_LIST_LIMIT, true]);
  });

  it("reports a missing table as unavailable and anything else as an error", async () => {
    expect((await listAllEngagements(fakeAdmin({ engagements: [{ error: { code: "42P01" } }] }).admin, null)).status).toBe("unavailable");
    expect((await listAllEngagements(fakeAdmin({ engagements: [{ error: { code: "XX000" } }] }).admin, null)).status).toBe("error");
  });
});

describe("loadEngagementView", () => {
  const engagementRow = { id: "eng-1", owner: "owner-1", state: "scoped" } as unknown as Parameters<typeof loadEngagementView>[1];
  const tables = () => ({
    engagement_scope_hosts: [{ data: [{ host: "shop.example.com", included: true }, { host: "www.example.com", included: true }, { host: "legacy.example.com", included: false }] }],
    offensive_scan_authorizations: [
      {
        data: [
          { target_host: "shop.example.com", authorized_at: "2026-11-02T00:00:00Z", expires_at: "2026-12-31T00:00:00Z", revoked_at: null },
          { target_host: "www.example.com", authorized_at: "2026-11-02T00:00:00Z", expires_at: "2026-11-03T00:00:00Z", revoked_at: null },
        ],
      },
    ],
    monitored_targets: [{ data: [{ target_url: "https://shop.example.com" }, { target_url: "https://SHOP.example.com/app" }, { target_url: "https://legacy.example.com" }, { target_url: "not a url" }] }],
    engagement_contacts: [{ data: [{ id: "c1", kind: "emergency" }] }],
    engagement_testing_windows: [{ data: [] }],
  });

  it("joins each scope host to its current linked authorisation and the owner's matching targets", async () => {
    const result = await loadEngagementView(fakeAdmin(tables()).admin, engagementRow, NOW);
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.data.scope).toEqual([
      { host: "shop.example.com", included: true, targetUrls: ["https://shop.example.com", "https://SHOP.example.com/app"], authorization: { authorized_at: "2026-11-02T00:00:00Z", expires_at: "2026-12-31T00:00:00Z" } },
      { host: "www.example.com", included: true, targetUrls: [], authorization: null },
      { host: "legacy.example.com", included: false, targetUrls: [], authorization: null },
    ]);
    expect(result.data.contacts).toEqual([{ id: "c1", kind: "emergency" }]);
  });

  it("fails on any failed read rather than showing a partial view", async () => {
    for (const table of ["engagement_scope_hosts", "offensive_scan_authorizations", "monitored_targets", "engagement_contacts", "engagement_testing_windows"] as const) {
      const t = tables();
      t[table] = [{ error: { code: "XX000" } }] as never;
      expect((await loadEngagementView(fakeAdmin(t).admin, engagementRow, NOW)).status, table).toBe("error");
    }
  });
});

describe("accountExists", () => {
  it("answers yes, no, or a failure", async () => {
    expect(await accountExists(fakeAdmin({ users: [{ data: { id: "u1" } }] }).admin, "u1")).toEqual({ status: "ok", data: true });
    expect(await accountExists(fakeAdmin({ users: [{ data: null }] }).admin, "u1")).toEqual({ status: "ok", data: false });
    expect((await accountExists(fakeAdmin({ users: [{ error: { code: "XX000" } }] }).admin, "u1")).status).toBe("error");
  });
});

describe("applyScopeChanges removals", () => {
  it("refuses a malformed host to remove, and audits the refusal", async () => {
    const { admin } = fakeAdmin({});
    const result = await applyScopeChanges(admin, ENGAGEMENT, "admin-1", { add: [], remove: ["https://a.test/path"] });
    expect(result).toEqual({ status: "ok", data: { added: [], removed: [], refused: [{ host: "https://a.test/path", reason: "invalid_host" }] } });
    expect(audit.mock.calls[0][1]).toMatchObject({ action: "engagement_scope.refused", metadata: { reason: "invalid_host" } });
  });
});
