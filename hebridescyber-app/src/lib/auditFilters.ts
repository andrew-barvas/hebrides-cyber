// Structured filtering for the admin audit log. The action vocabulary is a
// stable "<resource>.<verb>" scheme (see logAuditEvent in audit.ts), so the
// natural structured facet is the resource prefix — e.g. "stripe" matches
// every stripe.* action. Kept pure and unit-testable; the route feeds the
// query params through these and applies the result to the Supabase query.

/** Known action categories (the prefix before the first "."), with labels for the admin dropdown. */
export const AUDIT_CATEGORIES: { value: string; label: string }[] = [
  { value: "admin", label: "Admin actions" },
  { value: "stripe", label: "Billing (Stripe)" },
  { value: "scan", label: "Scans" },
  { value: "api_key", label: "API keys" },
  { value: "domain_verification", label: "Domain verification" },
  { value: "finding", label: "Findings" },
  { value: "share_link", label: "Share links" },
  { value: "team_member", label: "Team members" },
  { value: "account", label: "Account" },
  { value: "offensive_scan", label: "Offensive scans" },
  { value: "login_recorder", label: "Login recorder" },
  { value: "siem_integration", label: "SIEM integration" },
  { value: "sla_policy", label: "SLA policy" },
  { value: "webhook", label: "Webhooks" },
];

const CATEGORY_VALUES = new Set(AUDIT_CATEGORIES.map((c) => c.value));

/**
 * The SQL `LIKE` pattern matching every action in a category (e.g.
 * "stripe" → "stripe.%"). Returns null for an empty or unknown category, so
 * the caller applies no category filter rather than matching nothing.
 */
export function categoryLikePattern(category: string | undefined | null): string | null {
  if (!category) return null;
  const trimmed = category.trim();
  if (!CATEGORY_VALUES.has(trimmed)) return null;
  return `${trimmed}.%`;
}

export type DateBounds = { gte: string | null; lte: string | null };

/**
 * Turns `from`/`to` date strings (YYYY-MM-DD, or any Date.parse-able value)
 * into inclusive created_at bounds: `from` at the start of that day, `to` at
 * the very end of it, both in UTC. An empty or unparseable value yields a
 * null bound (no filter on that side) rather than a bogus one — never guess.
 */
export function dateRangeBounds(from: string | undefined | null, to: string | undefined | null): DateBounds {
  return { gte: startOfDayIso(from), lte: endOfDayIso(to) };
}

function startOfDayIso(value: string | undefined | null): string | null {
  const d = parseDateOnly(value);
  if (!d) return null;
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

function endOfDayIso(value: string | undefined | null): string | null {
  const d = parseDateOnly(value);
  if (!d) return null;
  d.setUTCHours(23, 59, 59, 999);
  return d.toISOString();
}

function parseDateOnly(value: string | undefined | null): Date | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  // A bare YYYY-MM-DD is parsed by JS as UTC midnight, which is what we want.
  const t = Date.parse(trimmed);
  if (!Number.isFinite(t)) return null;
  return new Date(t);
}
