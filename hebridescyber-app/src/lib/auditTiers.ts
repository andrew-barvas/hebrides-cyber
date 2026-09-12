// Shared source of truth for the three one-off audit tiers — the same
// name/price/description src/app/pricing/page.tsx's `oneOff` array shows
// publicly, kept here too so the dashboard's in-app "Request an audit" flow
// (src/pages/api/account/request-audit.ts) and its UI don't hand-copy those
// numbers a second place they could drift from.
//
// Each tier maps to the budget_range bucket contactOptions.ts already
// defines for it (see that file's header) — a request for one of these
// tiers is saved as an ordinary contact_enquiries row with that bucket set,
// so it shows up in the existing admin enquiries view with no schema change.
import type { BudgetRange } from "./contactOptions";

export const AUDIT_TIERS = [
  {
    id: "small",
    name: "Small Website Audit",
    price: "£300",
    desc: "Automated scan, headers & TLS checks, dependency scan, 1-page Security Score.",
    budgetRange: "under_300" as BudgetRange,
  },
  {
    id: "standard",
    name: "Standard Web App Audit",
    price: "£800",
    desc: "OWASP Top 10 manual testing, API testing, auth/session checks, 8–12 page report.",
    budgetRange: "300_800" as BudgetRange,
  },
  {
    id: "full",
    name: "Full SaaS Audit",
    price: "£1,800",
    desc: "Full manual pen test, CI/CD review, cloud permissions review, 20+ page report.",
    budgetRange: "800_1800" as BudgetRange,
  },
] as const;

export type AuditTierId = (typeof AUDIT_TIERS)[number]["id"];

export function isAuditTierId(value: unknown): value is AuditTierId {
  return typeof value === "string" && AUDIT_TIERS.some((t) => t.id === value);
}

export function getAuditTier(id: AuditTierId) {
  return AUDIT_TIERS.find((t) => t.id === id)!;
}
