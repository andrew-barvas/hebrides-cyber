import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { workspaceFindings, listWorkspaceUsers, MAX_USERS, type WorkspaceUser } from "./workspacePosture";

const user = (o: Partial<WorkspaceUser>): WorkspaceUser => ({ primaryEmail: "u@x.com", isAdmin: false, isEnrolledIn2Sv: true, isEnforcedIn2Sv: true, ...o });

describe("workspaceFindings", () => {
  it("flags super admins without 2SV, unenforced 2SV and too many super admins", () => {
    const users = [
      user({ primaryEmail: "boss@x.com", isAdmin: true, isEnrolledIn2Sv: false, isEnforcedIn2Sv: false }),
      ...[1, 2, 3, 4].map((n) => user({ primaryEmail: `a${n}@x.com`, isAdmin: true })),
      user({ primaryEmail: "staff@x.com", isEnforcedIn2Sv: false }),
      user({ primaryEmail: "gone@x.com", isEnforcedIn2Sv: false, suspended: true }),
    ];
    const findings = workspaceFindings(users);
    expect(findings.map((f) => [f.checkId, f.severity])).toEqual([
      ["workspace.adminsWithout2sv", "critical"],
      ["workspace.2svNotEnforced", "high"],
      ["workspace.tooManySuperAdmins", "medium"],
    ]);
    expect(findings[0].detail).toContain("boss@x.com");
    expect(findings[1].title).toContain("2 of 6 active users"); // the suspended account is ignored
    expect(findings.every((f) => f.remediation)).toBe(true);
  });

  it("is clean for a hardened Workspace, and flags a single super admin", () => {
    expect(workspaceFindings([user({ isAdmin: true }), user({ isAdmin: true }), user({})])).toEqual([]);
    expect(workspaceFindings([user({ isAdmin: true }), user({})]).map((f) => f.checkId)).toEqual(["workspace.singleSuperAdmin"]);
  });
});

describe("listWorkspaceUsers", () => {
  afterEach(() => vi.unstubAllGlobals());
  beforeEach(() => vi.restoreAllMocks());

  it("follows pageToken and returns every user", async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      url.includes("pageToken") ? new Response(JSON.stringify({ users: [user({ primaryEmail: "b@x.com" })] })) : new Response(JSON.stringify({ users: [user({ primaryEmail: "a@x.com" })], nextPageToken: "p2" }))
    ) as unknown as typeof fetch;
    const r = await listWorkspaceUsers("tok", fetchImpl);
    expect(r).toEqual({ ok: true, users: [expect.objectContaining({ primaryEmail: "a@x.com" }), expect.objectContaining({ primaryEmail: "b@x.com" })] });
  });

  it("reports a refused read or too many users as an error, never a clean list", async () => {
    expect(await listWorkspaceUsers("tok", (async () => new Response("", { status: 403 })) as unknown as typeof fetch)).toEqual({ ok: false, error: "users: HTTP 403" });
    const many = Array.from({ length: MAX_USERS + 1 }, () => user({}));
    const r = await listWorkspaceUsers("tok", (async () => new Response(JSON.stringify({ users: many }))) as unknown as typeof fetch);
    expect(r.ok).toBe(false);
  });
});
