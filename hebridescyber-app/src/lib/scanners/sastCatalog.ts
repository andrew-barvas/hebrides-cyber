// The SAST rule pack's catalogue, on the TypeScript side: which weakness
// category each of our own Opengrep rules (hebridescyber-app/sast-rules/)
// belongs to. Pure data, no I/O — imported by src/worker/tools/sast.ts (to
// pick remediation text), compliance.ts and fixDifficulty.ts (both of which
// key on a finding's base checkId, "sast.<rule-id>", so they need one entry
// per rule).
//
// The rule YAML files are the source of truth for each rule's CWE;
// sastCatalog.test.ts reads them and fails if a rule is missing here, or if
// the category recorded here disagrees with the category its CWE maps to.
// So adding a rule to the pack means adding one line below.

export type SastCategory =
  | "sql-injection"
  | "code-injection"
  | "command-injection"
  | "file-inclusion"
  | "deserialization"
  | "open-redirect"
  | "tls-verification"
  | "debug-mode"
  | "jwt-verification";

/** CWE id → category. Only CWEs our rules actually cite. */
export const SAST_CWE_CATEGORY: Record<string, SastCategory> = {
  "CWE-89": "sql-injection",
  "CWE-94": "code-injection",
  "CWE-95": "code-injection",
  "CWE-78": "command-injection",
  "CWE-98": "file-inclusion",
  "CWE-502": "deserialization",
  "CWE-601": "open-redirect",
  "CWE-295": "tls-verification",
  "CWE-489": "debug-mode",
  "CWE-347": "jwt-verification",
};

/** Human-readable label used in finding titles. */
export const SAST_CATEGORY_LABELS: Record<SastCategory, string> = {
  "sql-injection": "SQL injection",
  "code-injection": "Code injection",
  "command-injection": "OS command injection",
  "file-inclusion": "File inclusion",
  deserialization: "Unsafe deserialisation",
  "open-redirect": "Open redirect",
  "tls-verification": "TLS certificate verification disabled",
  "debug-mode": "Debug mode enabled",
  "jwt-verification": "JWT signature verification disabled",
};

/** Every rule id in sast-rules/, by category. */
export const SAST_RULE_CATEGORIES: Record<string, SastCategory> = {
  // JavaScript / TypeScript
  "js-sql-injection": "sql-injection",
  "js-sql-injection-raw-query": "sql-injection",
  "js-code-injection": "code-injection",
  "js-code-injection-vm": "code-injection",
  "js-command-injection": "command-injection",
  "js-command-injection-shell-option": "command-injection",
  "js-unsafe-deserialization": "deserialization",
  "js-open-redirect": "open-redirect",
  "js-tls-verification-disabled": "tls-verification",
  "js-tls-verification-disabled-env": "tls-verification",
  "js-jwt-none-algorithm": "jwt-verification",
  // Python
  "py-sql-injection": "sql-injection",
  "py-sql-injection-raw-query": "sql-injection",
  "py-code-injection": "code-injection",
  "py-command-injection-subprocess-shell": "command-injection",
  "py-command-injection-os-system": "command-injection",
  "py-pickle-untrusted": "deserialization",
  "py-yaml-unsafe-load": "deserialization",
  "py-open-redirect": "open-redirect",
  "py-tls-verification-disabled": "tls-verification",
  "py-ssl-unverified-context": "tls-verification",
  "py-flask-debug-enabled": "debug-mode",
  "py-django-debug-enabled": "debug-mode",
  "py-jwt-verification-disabled": "jwt-verification",
  // PHP
  "php-sql-injection": "sql-injection",
  "php-sql-injection-pdo": "sql-injection",
  "php-sql-injection-framework": "sql-injection",
  "php-code-injection": "code-injection",
  "php-command-injection": "command-injection",
  "php-file-inclusion": "file-inclusion",
  "php-unserialize-untrusted": "deserialization",
  "php-open-redirect": "open-redirect",
  "php-tls-verification-disabled": "tls-verification",
  "php-laravel-debug-enabled": "debug-mode",
};

/** Pulls "CWE-89" out of strings like "CWE-89: Improper Neutralization ...". */
export function extractCweIds(cwe: unknown): string[] {
  const values = Array.isArray(cwe) ? cwe : cwe === undefined || cwe === null ? [] : [cwe];
  const ids = new Set<string>();
  for (const v of values) {
    if (typeof v !== "string") continue;
    const m = v.match(/CWE-\d+/i);
    if (m) ids.add(m[0].toUpperCase());
  }
  return [...ids];
}

/** First CWE that maps to a category, or null — never a guessed category. */
export function sastCategoryForCwes(cweIds: string[]): SastCategory | null {
  for (const id of cweIds) {
    const category = SAST_CWE_CATEGORY[id];
    if (category) return category;
  }
  return null;
}
