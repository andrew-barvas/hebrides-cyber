import { describe, it, expect, vi } from "vitest";
import {
  checkSecurityBaseline,
  checkMfaAllUsers,
  checkMfaAdmins,
  checkLegacyAuth,
  checkGlobalAdmins,
  checkExternalForwarding,
  checkGuestAccess,
  checkUserConsent,
  checkSignInLogs,
  externalRecipients,
  runM365Checks,
  runM365PostureChecks,
  summariseM365,
  GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
  GUEST_ROLE_SAME_AS_MEMBER,
  MAX_MAILBOXES,
  type ConditionalAccessPolicy,
  type MessageRule,
} from "./m365Posture";
import { createGraphClient, GRAPH_BASE, type GraphResult } from "../m365Graph";
import { getComplianceRefs } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";
import { getAttackRefs } from "./attackMap";
import type { SupabaseClient } from "@supabase/supabase-js";

// Hand-built Graph v1.0 JSON, trimmed to the fields the checks read. Shapes
// follow Microsoft's documented responses for each endpoint.

const okBody = <T,>(body: T): GraphResult<T> => ({ ok: true, body });
const items = <T,>(list: T[], truncated = false) => okBody({ items: list, truncated });
const graphError = (status: number, code: string, message = code) => ({ ok: false as const, error: { status, code, message } });

const SD_OFF = okBody({ isEnabled: false });
const SD_ON = okBody({ isEnabled: true });

const MFA_ALL: ConditionalAccessPolicy = {
  displayName: "Require MFA for all users",
  state: "enabled",
  conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["all"] },
  grantControls: { builtInControls: ["mfa"] },
};
const MFA_ADMINS: ConditionalAccessPolicy = {
  displayName: "Require MFA for admins",
  state: "enabled",
  conditions: { users: { includeRoles: [GLOBAL_ADMIN_ROLE_TEMPLATE_ID] }, applications: { includeApplications: ["All"] } },
  grantControls: { builtInControls: [], authenticationStrength: { id: "00000000-0000-0000-0000-000000000002" } },
};
const BLOCK_LEGACY: ConditionalAccessPolicy = {
  displayName: "Block legacy authentication",
  state: "enabled",
  conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["exchangeActiveSync", "other"] },
  grantControls: { builtInControls: ["block"] },
};

describe("security defaults / Conditional Access", () => {
  it("passes every sign-in check when security defaults are on, without needing CA", () => {
    const ca = graphError(500, "serviceUnavailable");
    for (const check of [checkSecurityBaseline, checkMfaAllUsers, checkMfaAdmins, checkLegacyAuth]) {
      expect(check(SD_ON, ca)).toEqual(expect.objectContaining({ status: "checked", findings: [] }));
    }
  });

  it("passes with CA policies that enforce MFA and block legacy auth", () => {
    const ca = items([MFA_ALL, MFA_ADMINS, BLOCK_LEGACY]);
    for (const check of [checkSecurityBaseline, checkMfaAllUsers, checkMfaAdmins, checkLegacyAuth]) {
      expect(check(SD_OFF, ca).findings).toEqual([]);
    }
  });

  it("flags everything when defaults are off and there is no CA policy", () => {
    const ca = items<ConditionalAccessPolicy>([]);
    expect(checkSecurityBaseline(SD_OFF, ca).findings.map((f) => f.checkId)).toEqual(["m365.noSecurityBaseline"]);
    expect(checkMfaAllUsers(SD_OFF, ca).findings.map((f) => f.checkId)).toEqual(["m365.mfaNotEnforcedAllUsers"]);
    expect(checkMfaAdmins(SD_OFF, ca).findings[0]).toMatchObject({ checkId: "m365.mfaNotEnforcedAdmins", severity: "critical" });
    expect(checkLegacyAuth(SD_OFF, ca).findings.map((f) => f.checkId)).toEqual(["m365.legacyAuthAllowed"]);
  });

  it("doesn't count report-only or disabled policies", () => {
    const ca = items([
      { ...MFA_ALL, state: "enabledForReportingButNotEnforced" },
      { ...BLOCK_LEGACY, state: "disabled" },
    ]);
    expect(checkSecurityBaseline(SD_OFF, ca).findings).toHaveLength(1);
    expect(checkMfaAllUsers(SD_OFF, ca).findings).toHaveLength(1);
    expect(checkLegacyAuth(SD_OFF, ca).findings).toHaveLength(1);
  });

  it("treats an admin-only MFA policy as covering admins but not all users", () => {
    const ca = items([MFA_ADMINS]);
    expect(checkMfaAdmins(SD_OFF, ca).findings).toEqual([]);
    expect(checkMfaAllUsers(SD_OFF, ca).findings).toHaveLength(1);
    // Some enabled policy exists, so the baseline check passes.
    expect(checkSecurityBaseline(SD_OFF, ca).findings).toEqual([]);
  });

  it("needs both legacy client types and a block grant", () => {
    const onlyEas = { ...BLOCK_LEGACY, conditions: { ...BLOCK_LEGACY.conditions, clientAppTypes: ["exchangeActiveSync"] } };
    expect(checkLegacyAuth(SD_OFF, items([onlyEas])).findings).toHaveLength(1);
    const mfaNotBlock = { ...BLOCK_LEGACY, grantControls: { builtInControls: ["mfa"] } };
    expect(checkLegacyAuth(SD_OFF, items([mfaNotBlock])).findings).toHaveLength(1);
  });

  it("reads a licence refusal for CA as 'no policies', not an error", () => {
    const ca = graphError(403, "Forbidden", "Tenant does not have a SPO license / AAD Premium P1");
    expect(checkMfaAllUsers(SD_OFF, ca)).toMatchObject({ status: "checked", findings: [{ checkId: "m365.mfaNotEnforcedAllUsers" }] });
  });

  it("is an error, never clean, when a read it depends on fails (rule 7)", () => {
    const caDown = graphError(503, "serviceUnavailable");
    for (const check of [checkSecurityBaseline, checkMfaAllUsers, checkMfaAdmins, checkLegacyAuth]) {
      expect(check(SD_OFF, caDown).status).toBe("error");
      expect(check(graphError(403, "Authorization_RequestDenied"), items([])).status).toBe("error");
      expect(check(okBody({}), items([])).status).toBe("error");
    }
  });
});

describe("checkGlobalAdmins", () => {
  const user = (n: number) => ({ "@odata.type": "#microsoft.graph.user", id: `u${n}`, userPrincipalName: `admin${n}@contoso.test` });
  const sp = { "@odata.type": "#microsoft.graph.servicePrincipal", id: "sp1" };

  it("passes with two to four users, ignoring service principals", () => {
    expect(checkGlobalAdmins(items([user(1), user(2), sp])).findings).toEqual([]);
    expect(checkGlobalAdmins(items([user(1), user(2), user(3), user(4)])).findings).toEqual([]);
  });

  it("flags more than four", () => {
    const f = checkGlobalAdmins(items([1, 2, 3, 4, 5].map(user))).findings;
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "m365.tooManyGlobalAdmins", severity: "medium", title: "Microsoft 365: 5 Global Administrators" });
  });

  it("flags a truncated list as too many", () => {
    expect(checkGlobalAdmins(items([user(1), user(2)], true)).findings[0].title).toContain("more than 2");
  });

  it("flags a single admin as low", () => {
    expect(checkGlobalAdmins(items([user(1), sp])).findings[0]).toMatchObject({ checkId: "m365.singleGlobalAdmin", severity: "low" });
  });

  it("errors when the role members can't be read", () => {
    expect(checkGlobalAdmins(graphError(403, "Authorization_RequestDenied")).status).toBe("error");
  });
});

describe("external mailbox forwarding", () => {
  const verified = new Set(["contoso.test", "contoso.onmicrosoft.com"]);
  const to = (address: string) => ({ emailAddress: { address } });

  it("finds external addresses across forward, attachment and redirect actions", () => {
    const rule: MessageRule = {
      isEnabled: true,
      actions: { forwardTo: [to("Ally@Contoso.test"), to("x@gmail.test")], forwardAsAttachmentTo: [to("y@proton.test")], redirectTo: [to("x@gmail.test")] },
    };
    expect(externalRecipients(rule, verified).sort()).toEqual(["x@gmail.test", "y@proton.test"]);
  });

  it("ignores disabled rules and internal recipients", () => {
    expect(externalRecipients({ isEnabled: false, actions: { forwardTo: [to("x@gmail.test")] } }, verified)).toEqual([]);
    expect(externalRecipients({ isEnabled: true, actions: { redirectTo: [to("a@contoso.onmicrosoft.com")] } }, verified)).toEqual([]);
  });

  const domains = items([{ id: "contoso.test", isVerified: true }, { id: "pending.test", isVerified: false }]);
  const users = items([{ id: "id-1", userPrincipalName: "ally@contoso.test" }, { id: "id-2", userPrincipalName: "bo@contoso.test" }, { id: "id-3", userPrincipalName: "printer@contoso.test" }]);

  it("reports one finding per mailbox, keyed by object ID, and skips users with no mailbox", () => {
    const outcome = checkExternalForwarding(domains, users, [
      { user: { id: "id-1", userPrincipalName: "ally@contoso.test" }, rules: items([{ isEnabled: true, actions: { forwardTo: [to("ally.home@gmail.test")] } }]) },
      // An unverified domain counts as external.
      { user: { id: "id-2", userPrincipalName: "bo@contoso.test" }, rules: items([{ isEnabled: true, actions: { redirectTo: [to("bo@pending.test")] } }]) },
      { user: { id: "id-3", userPrincipalName: "printer@contoso.test" }, rules: graphError(404, "MailboxNotEnabledForRESTAPI") },
    ]);
    expect(outcome.status).toBe("checked");
    expect(outcome.findings.map((f) => f.checkId)).toEqual(["m365.externalForwarding:id-1", "m365.externalForwarding:id-2"]);
    expect(outcome.findings[0].detail).toContain("ally.home@gmail.test");
  });

  it("errors on a failed rule read but keeps the findings it did evidence", () => {
    const outcome = checkExternalForwarding(domains, users, [
      { user: { id: "id-1" }, rules: items([{ isEnabled: true, actions: { forwardTo: [to("x@gmail.test")] } }]) },
      { user: { id: "id-2" }, rules: graphError(429, "TooManyRequests") },
    ]);
    expect(outcome.status).toBe("error");
    expect(outcome.findings).toHaveLength(1);
  });

  it("errors rather than claiming clean when the user list was truncated", () => {
    const outcome = checkExternalForwarding(domains, items([{ id: "id-1" }], true), [{ user: { id: "id-1" }, rules: items([]) }]);
    expect(outcome).toMatchObject({ status: "error" });
    if (outcome.status === "error") expect(outcome.note).toContain(String(MAX_MAILBOXES));
  });

  it("errors when domains or users can't be read, or no domain is verified", () => {
    expect(checkExternalForwarding(graphError(500, "x"), users, []).status).toBe("error");
    expect(checkExternalForwarding(domains, graphError(500, "x"), []).status).toBe("error");
    expect(checkExternalForwarding(items([{ id: "a.test", isVerified: false }]), users, []).status).toBe("error");
  });
});

describe("authorization policy: guests and app consent", () => {
  const policy = (over: Record<string, unknown> = {}) =>
    okBody({
      guestUserRoleId: "10dae51f-b6af-4016-8d66-8c2a99b929b3",
      allowInvitesFrom: "adminsAndGuestInviters",
      defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-low"] },
      ...over,
    });

  it("passes the Microsoft defaults hardened per CIS", () => {
    expect(checkGuestAccess(policy()).findings).toEqual([]);
    expect(checkUserConsent(policy()).findings).toEqual([]);
    expect(checkUserConsent(policy({ defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } })).findings).toEqual([]);
  });

  it("flags member-equivalent guests and open invites", () => {
    const f = checkGuestAccess(policy({ guestUserRoleId: GUEST_ROLE_SAME_AS_MEMBER, allowInvitesFrom: "everyone" })).findings;
    expect(f.map((x) => x.checkId)).toEqual(["m365.guestAccessUnrestricted", "m365.guestInvitesUnrestricted"]);
  });

  it("flags legacy 'consent to any app'", () => {
    const outcome = checkUserConsent(policy({ defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] } }));
    expect(outcome.findings.map((f) => f.checkId)).toEqual(["m365.userConsentUnrestricted"]);
  });

  it("accepts the older collection-wrapped shape", () => {
    expect(checkGuestAccess(okBody({ value: [{ guestUserRoleId: GUEST_ROLE_SAME_AS_MEMBER, allowInvitesFrom: "none" }] })).findings).toHaveLength(1);
  });

  it("errors on a failed or incomplete read", () => {
    expect(checkGuestAccess(graphError(403, "Authorization_RequestDenied")).status).toBe("error");
    expect(checkGuestAccess(okBody({})).status).toBe("error");
    expect(checkUserConsent(graphError(500, "x")).status).toBe("error");
    expect(checkUserConsent(okBody({ guestUserRoleId: "x" })).status).toBe("error");
  });
});

describe("checkSignInLogs", () => {
  it("passes when the log is readable", () => {
    expect(checkSignInLogs(okBody({ value: [] }))).toEqual({ check: "signInLogs", status: "checked", findings: [] });
  });

  it("flags a non-premium tenant", () => {
    const outcome = checkSignInLogs(graphError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant"));
    expect(outcome.findings.map((f) => f.checkId)).toEqual(["m365.signInLogsUnavailable"]);
  });

  it("errors on any other failure", () => {
    expect(checkSignInLogs(graphError(403, "Authorization_RequestDenied", "Insufficient privileges")).status).toBe("error");
  });
});

describe("mappings", () => {
  const ALL = [
    "m365.noSecurityBaseline",
    "m365.mfaNotEnforcedAllUsers",
    "m365.mfaNotEnforcedAdmins",
    "m365.legacyAuthAllowed",
    "m365.tooManyGlobalAdmins",
    "m365.singleGlobalAdmin",
    "m365.externalForwarding:abc",
    "m365.guestAccessUnrestricted",
    "m365.guestInvitesUnrestricted",
    "m365.userConsentUnrestricted",
    "m365.signInLogsUnavailable",
  ];

  it("gives every m365 checkId compliance refs and a fix difficulty", () => {
    for (const id of ALL) {
      expect(getComplianceRefs(id).length, id).toBeGreaterThan(0);
      expect(getFixDifficulty(id), id).toBeDefined();
    }
  });

  it("maps the access checks to Cyber Essentials user access control and CIS Microsoft 365", () => {
    for (const id of ALL.filter((i) => i !== "m365.signInLogsUnavailable" && !i.startsWith("m365.externalForwarding"))) {
      const refs = getComplianceRefs(id);
      expect(refs, id).toContainEqual({ framework: "cyber-essentials", control: "User access control" });
      expect(refs.some((r) => r.framework === "cis-m365"), id).toBe(true);
    }
    expect(getComplianceRefs("m365.externalForwarding:x").some((r) => r.framework === "cis-m365")).toBe(true);
  });

  it("cites ATT&CK for the forwarding rule", () => {
    expect(getAttackRefs("m365.externalForwarding:x").map((r) => r.id)).toEqual(["T1114.003"]);
  });
});

// ---- End to end over a fake Graph -----------------------------------------

type Route = { status?: number; body: unknown };

/** fetch stand-in that answers Graph paths from a table; unknown paths 404. */
function fakeGraph(routes: Record<string, Route>) {
  const calls: string[] = [];
  const impl = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    const path = url.startsWith(GRAPH_BASE) ? decodeURIComponent(url.slice(GRAPH_BASE.length)) : url;
    const route = routes[path] ?? { status: 404, body: { error: { code: "ResourceNotFound", message: "not found" } } };
    return new Response(JSON.stringify(route.body), { status: route.status ?? 200, headers: { "Content-Type": "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

const ADMINS_PATH = `/directoryRoles(roleTemplateId='${GLOBAL_ADMIN_ROLE_TEMPLATE_ID}')/members?$select=id,userPrincipalName`;
const USERS_PATH = "/users?$select=id,userPrincipalName&$filter=accountEnabled eq true&$top=999";

function weakTenant(): Record<string, Route> {
  return {
    "/policies/identitySecurityDefaultsEnforcementPolicy": { body: { id: "00000000-0000-0000-0000-000000000005", isEnabled: false } },
    "/identity/conditionalAccess/policies": { body: { value: [] } },
    [ADMINS_PATH]: {
      body: {
        value: [1, 2, 3, 4, 5, 6].map((n) => ({ "@odata.type": "#microsoft.graph.user", id: `a${n}`, userPrincipalName: `admin${n}@contoso.test` })),
      },
    },
    "/policies/authorizationPolicy": {
      body: {
        id: "authorizationPolicy",
        allowInvitesFrom: "everyone",
        guestUserRoleId: GUEST_ROLE_SAME_AS_MEMBER,
        defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] },
      },
    },
    "/auditLogs/signIns?$top=1": { status: 403, body: { error: { code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", message: "Tenant is not a B2C tenant and doesn't have premium license" } } },
    "/domains?$select=id,isVerified": { body: { value: [{ id: "contoso.test", isVerified: true }] } },
    [USERS_PATH]: {
      body: { value: [{ id: "u1", userPrincipalName: "ally@contoso.test" }], "@odata.nextLink": `${GRAPH_BASE}/users?page=2` },
    },
    "/users?page=2": { body: { value: [{ id: "u2", userPrincipalName: "bo@contoso.test" }] } },
    "/users/u1/mailFolders/inbox/messageRules": {
      body: { value: [{ id: "r1", displayName: "fwd", isEnabled: true, actions: { forwardTo: [{ emailAddress: { name: "Me", address: "ally@gmail.test" } }] } }] },
    },
    "/users/u2/mailFolders/inbox/messageRules": { body: { value: [] } },
  };
}

describe("runM365Checks over a fake Graph", () => {
  it("finds every weakness in a weak tenant, following nextLink", async () => {
    const { impl, calls } = fakeGraph(weakTenant());
    const result = summariseM365("t", await runM365Checks(createGraphClient("token", impl)));
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.findings.map((f) => f.checkId).sort()).toEqual(
      [
        "m365.externalForwarding:u1",
        "m365.guestAccessUnrestricted",
        "m365.guestInvitesUnrestricted",
        "m365.legacyAuthAllowed",
        "m365.mfaNotEnforcedAdmins",
        "m365.mfaNotEnforcedAllUsers",
        "m365.noSecurityBaseline",
        "m365.signInLogsUnavailable",
        "m365.tooManyGlobalAdmins",
        "m365.userConsentUnrestricted",
      ].sort()
    );
    expect(calls.some((c) => c.includes("page=2"))).toBe(true);
    // Read-only: every Graph call is a GET with no body.
    for (const [, init] of (impl as unknown as ReturnType<typeof vi.fn>).mock.calls) expect((init as RequestInit | undefined)?.method ?? "GET").toBe("GET");
  });

  it("is clean for a hardened tenant", async () => {
    const routes = weakTenant();
    routes["/policies/identitySecurityDefaultsEnforcementPolicy"] = { body: { isEnabled: true } };
    routes[ADMINS_PATH] = { body: { value: [1, 2].map((n) => ({ "@odata.type": "#microsoft.graph.user", id: `a${n}` })) } };
    routes["/policies/authorizationPolicy"] = {
      body: { allowInvitesFrom: "adminsAndGuestInviters", guestUserRoleId: "2af84b1e-32c8-42b7-82bc-daa82404023b", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } },
    };
    routes["/auditLogs/signIns?$top=1"] = { body: { value: [{ id: "s1" }] } };
    routes["/users/u1/mailFolders/inbox/messageRules"] = { body: { value: [] } };
    const { impl } = fakeGraph(routes);
    const result = summariseM365("t", await runM365Checks(createGraphClient("token", impl)));
    expect(result).toMatchObject({ status: "checked", findings: [] });
  });

  it("is an error overall when one read fails, keeping the other checks' findings", async () => {
    const routes = weakTenant();
    routes["/policies/authorizationPolicy"] = { status: 503, body: { error: { code: "serviceUnavailable", message: "try later" } } };
    const { impl } = fakeGraph(routes);
    const result = summariseM365("t", await runM365Checks(createGraphClient("token", impl)));
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("guestAccess");
    expect(result.note).toContain("userConsent");
    expect(result.findings.some((f) => f.checkId === "m365.tooManyGlobalAdmins")).toBe(true);
  });

  it("refuses a nextLink pointing off Graph", async () => {
    const routes = weakTenant();
    routes[USERS_PATH] = { body: { value: [], "@odata.nextLink": "https://evil.test/users" } };
    const { impl, calls } = fakeGraph(routes);
    const outcomes = await runM365Checks(createGraphClient("token", impl));
    expect(outcomes.find((o) => o.check === "externalForwarding")?.status).toBe("error");
    expect(calls.some((c) => c.startsWith("https://evil.test"))).toBe(false);
  });
});

describe("runM365PostureChecks", () => {
  const CONFIG = { clientId: "11111111-1111-1111-1111-111111111111", clientSecret: "s" };
  const TENANT = "22222222-2222-2222-2222-222222222222";

  function supabaseWith(row: { tenant_id: string } | null, error: { message: string } | null = null) {
    const update = vi.fn(() => ({ eq: () => Promise.resolve({ error: null }) }));
    const client = {
      from: () => ({
        select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: row, error }) }) }),
        update,
      }),
    };
    return { client: client as unknown as SupabaseClient, update };
  }

  const jwt = (claims: object) => `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.s`;

  function withToken(routes: Record<string, Route>, tokenStatus = 200) {
    const graph = fakeGraph(routes);
    const impl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).startsWith("https://login.microsoftonline.com/")) {
        return tokenStatus === 200
          ? new Response(JSON.stringify({ access_token: jwt({ tid: TENANT, roles: [] }) }), { status: 200 })
          : new Response(JSON.stringify({ error: "unauthorized_client", error_description: "AADSTS700016: Application not found in the directory" }), { status: tokenStatus });
      }
      return graph.impl(input, init);
    });
    return impl as unknown as typeof fetch;
  }

  it("is not_configured without app credentials or a connected tenant", async () => {
    expect((await runM365PostureChecks(supabaseWith(null).client, "o", { config: null })).status).toBe("not_configured");
    expect((await runM365PostureChecks(supabaseWith(null).client, "o", { config: CONFIG })).status).toBe("not_configured");
  });

  it("is an error when the tenant row can't be read", async () => {
    expect((await runM365PostureChecks(supabaseWith(null, { message: "db down" }).client, "o", { config: CONFIG })).status).toBe("error");
  });

  it("is an error, with no findings, when consent was removed", async () => {
    const result = await runM365PostureChecks(supabaseWith({ tenant_id: TENANT }).client, "o", { config: CONFIG, fetchImpl: withToken(weakTenant(), 400) });
    expect(result).toMatchObject({ status: "error", findings: [] });
    if (result.status === "error") expect(result.note).toContain("AADSTS700016");
  });

  it("checks the tenant and records last_checked_at", async () => {
    const { client, update } = supabaseWith({ tenant_id: TENANT });
    const result = await runM365PostureChecks(client, "o", { config: CONFIG, fetchImpl: withToken(weakTenant()), now: () => new Date("2026-11-01T00:00:00Z") });
    expect(result.status).toBe("checked");
    expect(update).toHaveBeenCalledWith({ last_checked_at: "2026-11-01T00:00:00.000Z" });
  });
});
