// Keeps the TypeScript catalogue in step with zizmor's real audit list, so a
// finding from any audit zizmor can emit gets a category (never silently
// uncategorised) and downstream compliance/fixDifficulty/remediation entries.
import { describe, it, expect } from "vitest";
import {
  WORKFLOW_SECURITY_IDENT_CATEGORIES,
  WORKFLOW_SECURITY_CATEGORY_LABELS,
  workflowSecurityCategoryForIdent,
  type WorkflowSecurityCategory,
} from "./workflowSecurityCatalog";
import { getComplianceRefs } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";
import { workflowSecurityRemediation } from "./remediationText";

// Every audit module in crates/zizmor/src/audit/mod.rs at tag v1.30.1
// (https://raw.githubusercontent.com/zizmorcore/zizmor/v1.30.1/crates/zizmor/src/audit/mod.rs),
// module names converted from snake_case to the hyphenated `ident` zizmor's
// JSON output actually uses (confirmed against a real v1.30.1 scan — see
// fixtures/zizmor-scan.json). Never hand-guessed.
const REAL_ZIZMOR_IDENTS = [
  "adhoc-packages", "anonymous-definition", "archived-uses", "artipacked", "bot-conditions",
  "cache-poisoning", "concurrency-limits", "dangerous-triggers", "dependabot-cooldown",
  "dependabot-execution", "excessive-permissions", "forbidden-uses", "github-app", "github-env",
  "hardcoded-container-credentials", "impostor-commit", "insecure-commands", "insecure-url-scheme",
  "known-vulnerable-actions", "misfeature", "obfuscation", "overprovisioned-secrets", "ref-confusion",
  "ref-version-mismatch", "secrets-inherit", "secrets-outside-env", "self-hosted-runner",
  "self-repository", "stale-action-refs", "superfluous-actions", "template-injection",
  "typosquat-uses", "undocumented-permissions", "unpinned-images", "unpinned-tools", "unpinned-uses",
  "unredacted-secrets", "unsound-condition", "unsound-contains", "unsound-ternary",
  "use-trusted-publishing",
] as const;

const ALL_CATEGORIES: WorkflowSecurityCategory[] = [
  "injection", "dangerous-triggers", "excessive-permissions", "supply-chain-integrity",
  "credential-exposure", "unsound-logic", "hygiene",
];

describe("zizmor audit ident catalogue", () => {
  it("has exactly the real v1.30.1 audit idents, no more and no fewer", () => {
    expect(Object.keys(WORKFLOW_SECURITY_IDENT_CATEGORIES).sort()).toEqual([...REAL_ZIZMOR_IDENTS].sort());
  });

  it("maps every ident to a known category", () => {
    for (const ident of REAL_ZIZMOR_IDENTS) {
      expect(ALL_CATEGORIES).toContain(WORKFLOW_SECURITY_IDENT_CATEGORIES[ident]);
    }
  });

  it("falls back to hygiene for an ident zizmor adds later, never throwing", () => {
    expect(workflowSecurityCategoryForIdent("some-future-audit")).toBe("hygiene");
  });

  it("has a human-readable label for every category", () => {
    for (const category of ALL_CATEGORIES) {
      expect(WORKFLOW_SECURITY_CATEGORY_LABELS[category]).toBeTruthy();
    }
  });

  it("gives every ident compliance refs, a fix difficulty and non-empty remediation", () => {
    for (const ident of REAL_ZIZMOR_IDENTS) {
      const checkId = `workflow-security.${ident}`;
      expect(getComplianceRefs(checkId).length).toBeGreaterThan(0);
      expect(getFixDifficulty(checkId)).toBeTruthy();
      const category = WORKFLOW_SECURITY_IDENT_CATEGORIES[ident];
      expect(workflowSecurityRemediation(category, ident)).toContain(`#${ident}`);
    }
  });
});
