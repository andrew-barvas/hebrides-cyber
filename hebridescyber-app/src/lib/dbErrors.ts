// Shared helper for API routes reading/writing a table or column added by a
// migration that may not have been applied to this database yet.
//
// Postgres/PostgREST never throws for this — it resolves { data: null,
// error: { code: "42703" | "42P01", ... } } — so every call site must check
// `error.code` explicitly rather than relying on a catch block. This is the
// exact failure mode behind the 2026-09-15/09-18 incidents where new
// Dashboard widgets (notification prefs, cloud credentials, scheduled
// reports) hard-500'd on every load for any account whose migration hadn't
// landed yet — see docs/ENHANCEMENTS.md E-49/E-56.
//
// 42703 = undefined_column (migration added columns to an existing table).
// 42P01 = undefined_table (migration added a whole new table).
export function isMissingSchemaError(error: { code?: string | null } | null | undefined): boolean {
  return error?.code === "42703" || error?.code === "42P01";
}
