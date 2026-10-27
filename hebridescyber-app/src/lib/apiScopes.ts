// Scopes for API keys on the public API (/api/v1). A key carries a subset;
// a dashboard session is unscoped (it is the account owner at the keyboard).
// Mirrors the check constraint in migration 063 — change both together.
import type { NextApiResponse } from "next";

export const API_SCOPES = ["scans:read", "scans:write", "dependency:check"] as const;
export type ApiScope = (typeof API_SCOPES)[number];

export const API_SCOPE_DESCRIPTIONS: Record<ApiScope, string> = {
  "scans:read": "Read scans, findings, exports and trends",
  "scans:write": "Queue new scans",
  "dependency:check": "Run pull-request dependency checks",
};

/** Named bundles offered in the dashboard. */
export const API_KEY_PRESETS = {
  full: { label: "Full access", scopes: [...API_SCOPES] as ApiScope[] },
  ci: { label: "CI (scan + read results + dependency check)", scopes: ["scans:read", "scans:write", "dependency:check"] as ApiScope[] },
  read_only: { label: "Read-only (results and exports)", scopes: ["scans:read"] as ApiScope[] },
} as const;
export type ApiKeyPreset = keyof typeof API_KEY_PRESETS;

export function isApiScope(value: unknown): value is ApiScope {
  return typeof value === "string" && (API_SCOPES as readonly string[]).includes(value);
}

/** Scopes from storage, tolerant of a pre-063 row (column absent → all scopes, i.e. the old behaviour). */
export function scopesFromRow(value: unknown): ApiScope[] {
  if (!Array.isArray(value)) return [...API_SCOPES];
  return value.filter(isApiScope);
}

export type ScopedCaller = { scopes?: readonly ApiScope[] };

/** A caller with no `scopes` (a session) may do anything its account may. */
export function hasScope(caller: ScopedCaller, scope: ApiScope): boolean {
  return caller.scopes === undefined || caller.scopes.includes(scope);
}

/** Answers 403 `insufficient_scope` and returns false when the key lacks the scope. */
export function requireScope(caller: ScopedCaller, res: NextApiResponse, scope: ApiScope): boolean {
  if (hasScope(caller, scope)) return true;
  res.status(403).json({
    error: `This API key does not have the "${scope}" scope.`,
    code: "insufficient_scope",
    required_scope: scope,
  });
  return false;
}
