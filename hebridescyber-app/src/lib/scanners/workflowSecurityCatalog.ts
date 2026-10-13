// The zizmor audit catalogue, on the TypeScript side: which weakness
// category each of zizmor's own audit idents belongs to. Pure data, no I/O —
// imported by src/worker/tools/workflowSecurity.ts (to pick remediation
// text), compliance.ts and fixDifficulty.ts (both key on a finding's base
// checkId, "workflow-security.<ident>", so they need one entry per ident).
//
// Same shape as sastCatalog.ts, for the same reason: adding a category to
// zizmor's own audit list means adding one line below, and
// workflowSecurityCatalog.test.ts fails if an ident zizmor actually emits
// (checked against the real v1.30.1 source's audit module list) is missing
// here.
//
// Idents are zizmor's own, taken from a real v1.30.1 scan and from
// crates/zizmor/src/audit/mod.rs at the matching tag — never invented.

export type WorkflowSecurityCategory =
  | "injection"
  | "dangerous-triggers"
  | "excessive-permissions"
  | "supply-chain-integrity"
  | "credential-exposure"
  | "unsound-logic"
  | "hygiene";

export const WORKFLOW_SECURITY_CATEGORY_LABELS: Record<WorkflowSecurityCategory, string> = {
  injection: "Script/command injection",
  "dangerous-triggers": "Insecure workflow trigger",
  "excessive-permissions": "Excessive permissions or secret exposure",
  "supply-chain-integrity": "Action/dependency supply-chain integrity",
  "credential-exposure": "Credential exposure",
  "unsound-logic": "Unsound conditional logic",
  hygiene: "Workflow hygiene",
};

/** Every audit ident zizmor 1.30.1 can emit, by category. */
export const WORKFLOW_SECURITY_IDENT_CATEGORIES: Record<string, WorkflowSecurityCategory> = {
  "adhoc-packages": "supply-chain-integrity",
  "anonymous-definition": "hygiene",
  "archived-uses": "supply-chain-integrity",
  artipacked: "credential-exposure",
  "bot-conditions": "unsound-logic",
  "cache-poisoning": "supply-chain-integrity",
  "concurrency-limits": "hygiene",
  "dangerous-triggers": "dangerous-triggers",
  "dependabot-cooldown": "supply-chain-integrity",
  "dependabot-execution": "dangerous-triggers",
  "excessive-permissions": "excessive-permissions",
  "forbidden-uses": "supply-chain-integrity",
  "github-app": "credential-exposure",
  "github-env": "injection",
  "hardcoded-container-credentials": "credential-exposure",
  "impostor-commit": "supply-chain-integrity",
  "insecure-commands": "injection",
  "insecure-url-scheme": "supply-chain-integrity",
  "known-vulnerable-actions": "supply-chain-integrity",
  misfeature: "hygiene",
  obfuscation: "supply-chain-integrity",
  "overprovisioned-secrets": "excessive-permissions",
  "ref-confusion": "supply-chain-integrity",
  "ref-version-mismatch": "supply-chain-integrity",
  "secrets-inherit": "excessive-permissions",
  "secrets-outside-env": "credential-exposure",
  "self-hosted-runner": "hygiene",
  "self-repository": "dangerous-triggers",
  "stale-action-refs": "supply-chain-integrity",
  "superfluous-actions": "hygiene",
  "template-injection": "injection",
  "typosquat-uses": "supply-chain-integrity",
  "undocumented-permissions": "hygiene",
  "unpinned-images": "supply-chain-integrity",
  "unpinned-tools": "supply-chain-integrity",
  "unpinned-uses": "supply-chain-integrity",
  "unredacted-secrets": "credential-exposure",
  "unsound-condition": "unsound-logic",
  "unsound-contains": "unsound-logic",
  "unsound-ternary": "unsound-logic",
  "use-trusted-publishing": "supply-chain-integrity",
};

/**
 * A category for every known ident, falling back to "hygiene" for an ident
 * zizmor added after this catalogue was last updated — never an uncategorised
 * finding, since every one still needs remediation text and a severity.
 */
export function workflowSecurityCategoryForIdent(ident: string): WorkflowSecurityCategory {
  return WORKFLOW_SECURITY_IDENT_CATEGORIES[ident] ?? "hygiene";
}
