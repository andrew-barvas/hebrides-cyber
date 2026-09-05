// Value/label pairs for the contact form's optional lead-qualification
// fields (team size, budget range) — one source of truth shared by the
// form (src/app/contact/page.tsx), the API route (src/pages/api/contact.ts),
// and the admin UI (src/app/admin/page.tsx) so the three never drift apart.
// Values are stored as-is in contact_enquiries.team_size/budget_range
// (sql/migrations/019_contact_lead_qualification.sql's check constraints
// must match this list exactly).
//
// Budget buckets pair each real one-off audit price with the subscription
// tier it naturally corresponds to (src/app/pricing/page.tsx has the real,
// current numbers — never invent different ones here).
export const TEAM_SIZE_OPTIONS = [
  { value: "solo", label: "Just me" },
  { value: "2_10", label: "2–10" },
  { value: "11_50", label: "11–50" },
  { value: "51_200", label: "51–200" },
  { value: "200_plus", label: "200+" },
] as const;

export const BUDGET_RANGE_OPTIONS = [
  { value: "unsure", label: "Not sure yet" },
  { value: "under_300", label: "Under £300 (or ~£20/mo)" },
  { value: "300_800", label: "£300–£800 (or ~£35/mo)" },
  { value: "800_1800", label: "£800–£1,800 (or ~£75/mo)" },
  { value: "1800_plus", label: "£1,800+ (bespoke / multi-site)" },
] as const;

export type TeamSize = (typeof TEAM_SIZE_OPTIONS)[number]["value"];
export type BudgetRange = (typeof BUDGET_RANGE_OPTIONS)[number]["value"];

export function isTeamSize(value: unknown): value is TeamSize {
  return typeof value === "string" && TEAM_SIZE_OPTIONS.some((o) => o.value === value);
}

export function isBudgetRange(value: unknown): value is BudgetRange {
  return typeof value === "string" && BUDGET_RANGE_OPTIONS.some((o) => o.value === value);
}

export function teamSizeLabel(value: string | null | undefined): string | null {
  return TEAM_SIZE_OPTIONS.find((o) => o.value === value)?.label ?? null;
}

export function budgetRangeLabel(value: string | null | undefined): string | null {
  return BUDGET_RANGE_OPTIONS.find((o) => o.value === value)?.label ?? null;
}
