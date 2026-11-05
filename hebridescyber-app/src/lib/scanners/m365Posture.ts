// P1-4: Microsoft 365 / Entra ID posture — read-only checks of a customer's
// tenant for the settings behind most SME compromises. The customer's admin
// consents our multi-tenant app (src/pages/api/account/m365-connect.ts); the
// scan then reads configuration with an app-only Graph token for that tenant
// (src/lib/m365Graph.ts). Nothing here writes to the tenant.
//
// Each check is a pure function over the Graph JSON it needs, so the unit
// tests replay hand-built responses without a tenant. The runner fetches the
// JSON once and hands it to every check that uses it.
//
// Evidence discipline (CLAUDE.md rule 7): a Graph call that fails makes every
// check that depended on it "error", and any errored check makes the whole
// result "error", so findingLifecycle.ts never reads silence as a fix. Real
// detections from the checks that did run are still returned.
//
// What Graph can't see, and so these checks don't claim:
// - Mailbox-level forwarding (Exchange ForwardingSmtpAddress) and the outbound
//   spam policy's auto-forwarding switch are Exchange Online settings with no
//   Graph read. m365.externalForwarding covers inbox rules only.
// - The Purview unified audit log's on/off switch has no Graph read either.
//   m365.signInLogsUnavailable checks the Entra sign-in log is retained,
//   the audit trail an investigation of an account takeover needs first.
// - Per-user MFA (the legacy "enforced" toggle) and PIM-eligible role
//   assignments aren't read: MFA is judged from security defaults and
//   Conditional Access, Global Admins from active assignments.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./index";
import { createGraphClient, getAppToken, m365AppConfig, type GraphClient, type GraphError, type GraphResult, type M365AppConfig } from "../m365Graph";
import {
  M365_NO_BASELINE,
  M365_MFA_ALL_USERS,
  M365_MFA_ADMINS,
  M365_LEGACY_AUTH,
  M365_TOO_MANY_GLOBAL_ADMINS,
  M365_SINGLE_GLOBAL_ADMIN,
  M365_EXTERNAL_FORWARDING,
  M365_GUEST_ACCESS_OPEN,
  M365_GUEST_INVITES_OPEN,
  M365_USER_CONSENT_OPEN,
  M365_SIGN_IN_LOGS_UNAVAILABLE,
} from "./remediationText";

/** Role template IDs are fixed across every tenant. */
export const GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10";
/** authorizationPolicy.guestUserRoleId values (Entra built-ins). */
export const GUEST_ROLE_SAME_AS_MEMBER = "a0b1b346-4d3e-4e8b-98f8-753987be4970";

// CIS Microsoft 365 Foundations Benchmark: between two and four.
export const MAX_GLOBAL_ADMINS = 4;
const MIN_GLOBAL_ADMINS = 2;
// An SME tenant is far below this. Over it, the forwarding check reports
// "error" for the mailboxes it didn't reach rather than a clean result.
export const MAX_MAILBOXES = 1000;
const MAILBOX_CONCURRENCY = 8;

// ---- Graph shapes (only the fields read) -----------------------------------

export type SecurityDefaultsPolicy = { isEnabled?: boolean };

export type ConditionalAccessPolicy = {
  id?: string;
  displayName?: string;
  state?: "enabled" | "disabled" | "enabledForReportingButNotEnforced" | string;
  conditions?: {
    users?: { includeUsers?: string[]; includeRoles?: string[] };
    applications?: { includeApplications?: string[] };
    clientAppTypes?: string[];
  };
  grantControls?: { builtInControls?: string[]; authenticationStrength?: { id?: string } | null } | null;
};

export type DirectoryObject = { "@odata.type"?: string; id?: string; userPrincipalName?: string };

export type AuthorizationPolicy = {
  guestUserRoleId?: string;
  allowInvitesFrom?: "none" | "adminsAndGuestInviters" | "adminsGuestInvitersAndAllMembers" | "everyone" | string;
  defaultUserRolePermissions?: { permissionGrantPoliciesAssigned?: string[] };
};

export type GraphUser = { id?: string; userPrincipalName?: string };
export type Recipient = { emailAddress?: { address?: string } };
export type MessageRule = {
  id?: string;
  displayName?: string;
  isEnabled?: boolean;
  actions?: { forwardTo?: Recipient[]; forwardAsAttachmentTo?: Recipient[]; redirectTo?: Recipient[] };
};
export type Domain = { id?: string; isVerified?: boolean };

// ---- Results ---------------------------------------------------------------

export type M365CheckName =
  | "securityBaseline"
  | "mfaAllUsers"
  | "mfaAdmins"
  | "legacyAuth"
  | "globalAdmins"
  | "externalForwarding"
  | "guestAccess"
  | "userConsent"
  | "signInLogs";

export type M365CheckOutcome =
  | { check: M365CheckName; status: "checked"; findings: Finding[] }
  | { check: M365CheckName; status: "error"; note: string; findings: Finding[] };

export type M365Result =
  | { status: "not_configured"; note: string }
  | { status: "checked"; tenantId: string; checks: Array<{ check: M365CheckName; status: "checked" }>; findings: Finding[] }
  | { status: "error"; note: string; tenantId?: string; checks: Array<{ check: M365CheckName; status: "checked" | "error"; note?: string }>; findings: Finding[] };

const ok = (check: M365CheckName, findings: Finding[] = []): M365CheckOutcome => ({ check, status: "checked", findings });
const failed = (check: M365CheckName, note: string, findings: Finding[] = []): M365CheckOutcome => ({ check, status: "error", note, findings });
const explain = (e: GraphError) => `${e.code} (HTTP ${e.status})`;

// ---- Conditional Access helpers --------------------------------------------

function enforced(p: ConditionalAccessPolicy): boolean {
  return p.state === "enabled";
}

function coversAllUsers(p: ConditionalAccessPolicy): boolean {
  return (p.conditions?.users?.includeUsers ?? []).includes("All");
}

function coversAllApps(p: ConditionalAccessPolicy): boolean {
  return (p.conditions?.applications?.includeApplications ?? []).includes("All");
}

function requiresMfa(p: ConditionalAccessPolicy): boolean {
  const g = p.grantControls;
  return Boolean(g && ((g.builtInControls ?? []).includes("mfa") || g.authenticationStrength?.id));
}

/**
 * Listing Conditional Access needs Entra ID P1. A tenant without it can't have
 * a policy, which is evidence ("no CA") rather than a failed read — but only
 * when Microsoft says so in as many words. Anything else stays an error.
 */
export function caUnavailableForLicence(e: GraphError): boolean {
  return e.status === 403 && /premium|licen[cs]e|P1/i.test(`${e.code} ${e.message}`);
}

type CaInput = GraphResult<{ items: ConditionalAccessPolicy[]; truncated: boolean }>;

/** Enabled CA policies, [] for an unlicensed tenant, or the error that stopped us reading them. */
function enforcedPolicies(ca: CaInput): { policies: ConditionalAccessPolicy[] } | { error: string } {
  if (!ca.ok) return caUnavailableForLicence(ca.error) ? { policies: [] } : { error: explain(ca.error) };
  return { policies: ca.body.items.filter(enforced) };
}

function readSecurityDefaults(sd: GraphResult<SecurityDefaultsPolicy>): { on: boolean } | { error: string } {
  if (!sd.ok) return { error: explain(sd.error) };
  if (typeof sd.body.isEnabled !== "boolean") return { error: "security defaults policy had no isEnabled" };
  return { on: sd.body.isEnabled };
}

// ---- Checks (pure) ----------------------------------------------------------

/** Security defaults or at least one enforced Conditional Access policy. */
export function checkSecurityBaseline(sd: GraphResult<SecurityDefaultsPolicy>, ca: CaInput): M365CheckOutcome {
  const defaults = readSecurityDefaults(sd);
  if ("error" in defaults) return failed("securityBaseline", `security defaults: ${defaults.error}`);
  if (defaults.on) return ok("securityBaseline");
  const policies = enforcedPolicies(ca);
  if ("error" in policies) return failed("securityBaseline", `conditional access: ${policies.error}`);
  if (policies.policies.length > 0) return ok("securityBaseline");
  return ok("securityBaseline", [
    {
      severity: "high",
      title: "Microsoft 365: neither security defaults nor Conditional Access is on",
      detail: "Security defaults are disabled and the tenant has no enabled Conditional Access policy, so nothing enforces MFA or blocks legacy sign-in protocols.",
      checkId: "m365.noSecurityBaseline",
      remediation: M365_NO_BASELINE,
    },
  ]);
}

export function checkMfaAllUsers(sd: GraphResult<SecurityDefaultsPolicy>, ca: CaInput): M365CheckOutcome {
  const defaults = readSecurityDefaults(sd);
  if ("error" in defaults) return failed("mfaAllUsers", `security defaults: ${defaults.error}`);
  if (defaults.on) return ok("mfaAllUsers");
  const policies = enforcedPolicies(ca);
  if ("error" in policies) return failed("mfaAllUsers", `conditional access: ${policies.error}`);
  if (policies.policies.some((p) => coversAllUsers(p) && coversAllApps(p) && requiresMfa(p))) return ok("mfaAllUsers");
  return ok("mfaAllUsers", [
    {
      severity: "high",
      title: "Microsoft 365: MFA isn't required for all users",
      detail: "Security defaults are off and no enabled Conditional Access policy requires MFA for all users on all cloud apps. Policies in report-only mode don't count: they log but don't enforce.",
      checkId: "m365.mfaNotEnforcedAllUsers",
      remediation: M365_MFA_ALL_USERS,
    },
  ]);
}

export function checkMfaAdmins(sd: GraphResult<SecurityDefaultsPolicy>, ca: CaInput): M365CheckOutcome {
  const defaults = readSecurityDefaults(sd);
  if ("error" in defaults) return failed("mfaAdmins", `security defaults: ${defaults.error}`);
  if (defaults.on) return ok("mfaAdmins");
  const policies = enforcedPolicies(ca);
  if ("error" in policies) return failed("mfaAdmins", `conditional access: ${policies.error}`);
  const coversGlobalAdmin = (p: ConditionalAccessPolicy) =>
    coversAllUsers(p) || (p.conditions?.users?.includeRoles ?? []).includes(GLOBAL_ADMIN_ROLE_TEMPLATE_ID);
  if (policies.policies.some((p) => coversGlobalAdmin(p) && coversAllApps(p) && requiresMfa(p))) return ok("mfaAdmins");
  return ok("mfaAdmins", [
    {
      severity: "critical",
      title: "Microsoft 365: MFA isn't required for administrators",
      detail: "Security defaults are off and no enabled Conditional Access policy requires MFA for the Global Administrator role on all cloud apps.",
      checkId: "m365.mfaNotEnforcedAdmins",
      remediation: M365_MFA_ADMINS,
    },
  ]);
}

export function checkLegacyAuth(sd: GraphResult<SecurityDefaultsPolicy>, ca: CaInput): M365CheckOutcome {
  const defaults = readSecurityDefaults(sd);
  if ("error" in defaults) return failed("legacyAuth", `security defaults: ${defaults.error}`);
  if (defaults.on) return ok("legacyAuth");
  const policies = enforcedPolicies(ca);
  if ("error" in policies) return failed("legacyAuth", `conditional access: ${policies.error}`);
  const blocksLegacy = (p: ConditionalAccessPolicy) => {
    const types = p.conditions?.clientAppTypes ?? [];
    return (
      coversAllUsers(p) &&
      types.includes("exchangeActiveSync") &&
      types.includes("other") &&
      (p.grantControls?.builtInControls ?? []).includes("block")
    );
  };
  if (policies.policies.some(blocksLegacy)) return ok("legacyAuth");
  return ok("legacyAuth", [
    {
      severity: "high",
      title: "Microsoft 365: legacy authentication isn't blocked",
      detail: "Security defaults are off and no enabled Conditional Access policy blocks the Exchange ActiveSync and other legacy client types for all users. Legacy protocols can't do MFA, so they bypass it.",
      checkId: "m365.legacyAuthAllowed",
      remediation: M365_LEGACY_AUTH,
    },
  ]);
}

export function checkGlobalAdmins(members: GraphResult<{ items: DirectoryObject[]; truncated: boolean }>): M365CheckOutcome {
  if (!members.ok) return failed("globalAdmins", `global admin members: ${explain(members.error)}`);
  // Service principals can hold the role too, but the CIS count is people.
  const users = members.body.items.filter((m) => m["@odata.type"] === "#microsoft.graph.user");
  const count = users.length;
  if (members.body.truncated || count > MAX_GLOBAL_ADMINS) {
    return ok("globalAdmins", [
      {
        severity: "medium",
        title: `Microsoft 365: ${members.body.truncated ? `more than ${count}` : count} Global Administrators`,
        detail: `The tenant has ${members.body.truncated ? `more than ${count}` : count} user accounts with the Global Administrator role assigned. CIS recommends no more than ${MAX_GLOBAL_ADMINS}; every extra one is another account whose compromise hands over the whole tenant.`,
        checkId: "m365.tooManyGlobalAdmins",
        remediation: M365_TOO_MANY_GLOBAL_ADMINS,
      },
    ]);
  }
  if (count < MIN_GLOBAL_ADMINS) {
    return ok("globalAdmins", [
      {
        severity: "low",
        title: `Microsoft 365: only ${count} Global Administrator`,
        detail: `The tenant has ${count} user account${count === 1 ? "" : "s"} with the Global Administrator role. With no second admin there's no way back in if that account is locked out. CIS recommends at least ${MIN_GLOBAL_ADMINS}.`,
        checkId: "m365.singleGlobalAdmin",
        remediation: M365_SINGLE_GLOBAL_ADMIN,
      },
    ]);
  }
  return ok("globalAdmins");
}

function recipientDomain(address: string): string | null {
  const at = address.lastIndexOf("@");
  return at === -1 ? null : address.slice(at + 1).toLowerCase();
}

/** Forwarding/redirect addresses in an enabled rule that aren't in one of the tenant's verified domains. */
export function externalRecipients(rule: MessageRule, verifiedDomains: ReadonlySet<string>): string[] {
  if (rule.isEnabled === false) return [];
  const a = rule.actions ?? {};
  const out = new Set<string>();
  for (const r of [...(a.forwardTo ?? []), ...(a.forwardAsAttachmentTo ?? []), ...(a.redirectTo ?? [])]) {
    const address = r.emailAddress?.address?.trim();
    if (!address) continue;
    const domain = recipientDomain(address);
    if (domain && !verifiedDomains.has(domain)) out.add(address.toLowerCase());
  }
  return [...out];
}

/** Graph's answer for a user with no Exchange Online mailbox: nothing to forward, so not an error. */
export function isNoMailbox(e: GraphError): boolean {
  return e.status === 404 || /MailboxNotEnabledForRESTAPI|MailboxNotFound|ResourceNotFound/i.test(e.code);
}

export type MailboxRules = { user: GraphUser; rules: GraphResult<{ items: MessageRule[]; truncated: boolean }> };

export function checkExternalForwarding(
  domains: GraphResult<{ items: Domain[]; truncated: boolean }>,
  users: GraphResult<{ items: GraphUser[]; truncated: boolean }>,
  mailboxes: MailboxRules[]
): M365CheckOutcome {
  if (!domains.ok) return failed("externalForwarding", `domains: ${explain(domains.error)}`);
  if (!users.ok) return failed("externalForwarding", `users: ${explain(users.error)}`);
  const verified = new Set(domains.body.items.filter((d) => d.isVerified && d.id).map((d) => d.id!.toLowerCase()));
  // With no verified domain we can't tell internal from external.
  if (verified.size === 0) return failed("externalForwarding", "no verified domains returned");

  const findings: Finding[] = [];
  const errors: string[] = [];
  for (const { user, rules } of mailboxes) {
    if (!rules.ok) {
      if (!isNoMailbox(rules.error)) errors.push(explain(rules.error));
      continue;
    }
    const external = new Set<string>();
    for (const rule of rules.body.items) for (const addr of externalRecipients(rule, verified)) external.add(addr);
    if (external.size === 0 || !user.id) continue;
    const who = user.userPrincipalName ?? user.id;
    findings.push({
      severity: "high",
      title: `Microsoft 365: mailbox forwards externally: ${who}`,
      detail: `An enabled inbox rule in ${who}'s mailbox forwards or redirects mail outside your verified domains, to ${[...external].sort().join(", ")}.`,
      // Keyed by the user's object ID: a UPN changes on rename, the ID never does.
      checkId: `m365.externalForwarding:${user.id}`,
      remediation: M365_EXTERNAL_FORWARDING,
    });
  }
  if (users.body.truncated) {
    return failed("externalForwarding", `more than ${MAX_MAILBOXES} users; mailboxes beyond that weren't checked`, findings);
  }
  if (errors.length > 0) {
    return failed("externalForwarding", `${errors.length} mailbox rule read(s) failed, first: ${errors[0]}`, findings);
  }
  return ok("externalForwarding", findings);
}

/** v1.0 returns the policy object; older shapes wrapped it in `value`. */
function unwrapAuthorizationPolicy(body: AuthorizationPolicy | { value?: AuthorizationPolicy[] }): AuthorizationPolicy | null {
  if ("value" in body && Array.isArray(body.value)) return body.value[0] ?? null;
  return body as AuthorizationPolicy;
}

export function checkGuestAccess(auth: GraphResult<AuthorizationPolicy | { value?: AuthorizationPolicy[] }>): M365CheckOutcome {
  if (!auth.ok) return failed("guestAccess", `authorization policy: ${explain(auth.error)}`);
  const policy = unwrapAuthorizationPolicy(auth.body);
  if (!policy || typeof policy.guestUserRoleId !== "string" || typeof policy.allowInvitesFrom !== "string") {
    return failed("guestAccess", "authorization policy missing guest settings");
  }
  const findings: Finding[] = [];
  if (policy.guestUserRoleId.toLowerCase() === GUEST_ROLE_SAME_AS_MEMBER) {
    findings.push({
      severity: "high",
      title: "Microsoft 365: guests have the same directory access as members",
      detail: "Guest user access is set to \"same access as members\", so any invited guest can enumerate every user, group and membership in the directory.",
      checkId: "m365.guestAccessUnrestricted",
      remediation: M365_GUEST_ACCESS_OPEN,
    });
  }
  if (policy.allowInvitesFrom === "everyone") {
    findings.push({
      severity: "medium",
      title: "Microsoft 365: anyone, including guests, can invite guests",
      detail: "Guest invite settings allow everyone in the organisation, guests included, to invite new guest users.",
      checkId: "m365.guestInvitesUnrestricted",
      remediation: M365_GUEST_INVITES_OPEN,
    });
  }
  return ok("guestAccess", findings);
}

// The built-in "users can consent to any app" grant policy. "-low" (verified
// publishers, low-risk permissions) is the CIS-accepted setting; none is best.
const LEGACY_USER_CONSENT = /^ManagePermissionGrantsForSelf\.microsoft-user-default-legacy$/i;

export function checkUserConsent(auth: GraphResult<AuthorizationPolicy | { value?: AuthorizationPolicy[] }>): M365CheckOutcome {
  if (!auth.ok) return failed("userConsent", `authorization policy: ${explain(auth.error)}`);
  const policy = unwrapAuthorizationPolicy(auth.body);
  const assigned = policy?.defaultUserRolePermissions?.permissionGrantPoliciesAssigned;
  if (!Array.isArray(assigned)) return failed("userConsent", "authorization policy missing permissionGrantPoliciesAssigned");
  if (!assigned.some((p) => LEGACY_USER_CONSENT.test(p))) return ok("userConsent");
  return ok("userConsent", [
    {
      severity: "high",
      title: "Microsoft 365: users can consent to any third-party app",
      detail: "User consent is set to allow any application, from any publisher, to be granted access to a user's data by that user alone. This is the setting consent-phishing attacks rely on.",
      checkId: "m365.userConsentUnrestricted",
      remediation: M365_USER_CONSENT_OPEN,
    },
  ]);
}

/** Sign-in logs exist only on P1/P2 tenants; Graph says so with this code. */
export function signInLogsUnlicensed(e: GraphError): boolean {
  return e.status === 403 && /NonPremiumTenant|premium|licen[cs]e/i.test(`${e.code} ${e.message}`);
}

export function checkSignInLogs(signIns: GraphResult<{ value?: unknown[] }>): M365CheckOutcome {
  if (signIns.ok) return ok("signInLogs");
  if (!signInLogsUnlicensed(signIns.error)) return failed("signInLogs", `sign-in logs: ${explain(signIns.error)}`);
  return ok("signInLogs", [
    {
      severity: "medium",
      title: "Microsoft 365: sign-in logs aren't retained",
      detail: "Microsoft refused to return Entra ID sign-in logs because the tenant has no Entra ID P1 or P2 licence, so there is no sign-in record to investigate an account takeover against.",
      checkId: "m365.signInLogsUnavailable",
      remediation: M365_SIGN_IN_LOGS_UNAVAILABLE,
    },
  ]);
}

// ---- Runner -----------------------------------------------------------------

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Fetches what every check needs and runs them all. Exported for the tests, which pass a GraphClient over recorded JSON. */
export async function runM365Checks(graph: GraphClient): Promise<M365CheckOutcome[]> {
  const [sd, ca, admins, auth, signIns, domains, users] = await Promise.all([
    graph.get<SecurityDefaultsPolicy>("/policies/identitySecurityDefaultsEnforcementPolicy"),
    graph.getAll<ConditionalAccessPolicy>("/identity/conditionalAccess/policies", 500),
    graph.getAll<DirectoryObject>(`/directoryRoles(roleTemplateId='${GLOBAL_ADMIN_ROLE_TEMPLATE_ID}')/members?$select=id,userPrincipalName`, 100),
    graph.get<AuthorizationPolicy>("/policies/authorizationPolicy"),
    graph.get<{ value?: unknown[] }>("/auditLogs/signIns?$top=1"),
    graph.getAll<Domain>("/domains?$select=id,isVerified", 500),
    graph.getAll<GraphUser>("/users?$select=id,userPrincipalName&$filter=accountEnabled eq true&$top=999", MAX_MAILBOXES),
  ]);

  const mailboxes: MailboxRules[] = users.ok
    ? await mapLimit(users.body.items.filter((u) => u.id), MAILBOX_CONCURRENCY, async (user) => ({
        user,
        rules: await graph.getAll<MessageRule>(`/users/${encodeURIComponent(user.id!)}/mailFolders/inbox/messageRules`, 500),
      }))
    : [];

  return [
    checkSecurityBaseline(sd, ca),
    checkMfaAllUsers(sd, ca),
    checkMfaAdmins(sd, ca),
    checkLegacyAuth(sd, ca),
    checkGlobalAdmins(admins),
    checkExternalForwarding(domains, users, mailboxes),
    checkGuestAccess(auth),
    checkUserConsent(auth),
    checkSignInLogs(signIns),
  ];
}

/** Folds per-check outcomes into the one status findingLifecycle.ts reads. */
export function summariseM365(tenantId: string, outcomes: M365CheckOutcome[]): M365Result {
  const findings = outcomes.flatMap((o) => o.findings);
  const errored = outcomes.filter((o): o is Extract<M365CheckOutcome, { status: "error" }> => o.status === "error");
  if (errored.length === 0) {
    return { status: "checked", tenantId, checks: outcomes.map((o) => ({ check: o.check, status: "checked" as const })), findings };
  }
  return {
    status: "error",
    tenantId,
    note: `${errored.length} of ${outcomes.length} Microsoft 365 checks failed: ${errored.map((o) => `${o.check} (${o.note})`).join("; ")}`,
    checks: outcomes.map((o) => (o.status === "error" ? { check: o.check, status: o.status, note: o.note } : { check: o.check, status: o.status })),
    findings,
  };
}

export type M365RunDeps = { config?: M365AppConfig | null; fetchImpl?: typeof fetch; now?: () => Date };

/** Orchestrator entry point (scanExecution.ts): looks up the owner's connected tenant and checks it. */
export async function runM365PostureChecks(supabaseAdmin: SupabaseClient, ownerId: string, deps: M365RunDeps = {}): Promise<M365Result> {
  const config = deps.config === undefined ? m365AppConfig() : deps.config;
  if (!config) return { status: "not_configured", note: "M365_CLIENT_ID / M365_CLIENT_SECRET not set on this deployment" };

  const { data: row, error } = await supabaseAdmin.from("m365_tenants").select("tenant_id").eq("owner", ownerId).maybeSingle();
  if (error) return { status: "error", note: `could not read m365_tenants: ${error.message}`, checks: [], findings: [] };
  if (!row?.tenant_id) return { status: "not_configured", note: "No Microsoft 365 tenant connected" };
  const tenantId = row.tenant_id as string;

  const token = await getAppToken(tenantId, config, deps.fetchImpl);
  if (!token.ok) {
    // Most often the admin removed our app from the tenant (AADSTS700016 /
    // AADSTS7000112). Either way nothing was read, so nothing is clean.
    return { status: "error", tenantId, note: `could not get a Graph token for the tenant: ${token.error.message}`, checks: [], findings: [] };
  }

  const result = summariseM365(tenantId, await runM365Checks(createGraphClient(token.body.accessToken, deps.fetchImpl)));
  if (result.status === "checked") {
    // Best-effort: shown on the integrations card, never gates the scan.
    await supabaseAdmin
      .from("m365_tenants")
      .update({ last_checked_at: (deps.now?.() ?? new Date()).toISOString() })
      .eq("owner", ownerId)
      .then(() => undefined, () => undefined);
  }
  return result;
}
