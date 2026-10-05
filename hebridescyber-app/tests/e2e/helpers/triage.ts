import type { ApiCall } from "./mocks";

// A stateful stand-in for /api/findings/triage (src/pages/api/findings/triage.ts):
// PUT upserts a record, DELETE removes it, GET lists the active ones, exactly
// as the report page consumes them. Pass `initial` to start with findings
// already triaged.

export type TriageItem = {
  targetHost: string;
  checkId: string;
  state: "accepted_risk" | "false_positive" | "snoozed";
  reason: string;
  expiresAt: string | null;
  active: boolean;
  triagedAt: string;
  createdAt: string;
  triagedBy: string;
  triagedByEmail: string;
};

export function triageRecord(checkId: string, state: TriageItem["state"], reason: string, expiresAt: string | null = null): TriageItem {
  return {
    targetHost: "example.com",
    checkId,
    state,
    reason,
    expiresAt,
    active: true,
    triagedAt: "2026-10-05T08:00:00.000Z",
    createdAt: "2026-10-05T08:00:00.000Z",
    triagedBy: "11111111-1111-4111-8111-111111111111",
    triagedByEmail: "e2e@example.com",
  };
}

export function triageApi(initial: TriageItem[] = []) {
  const items = new Map(initial.map((i) => [i.checkId, i]));
  const body = (call: ApiCall) => call.body as { checkId: string; state: TriageItem["state"]; reason: string; expiresAt: string | null };
  return {
    "GET /api/findings/triage": () => ({ json: { available: true, host: "example.com", items: [...items.values()] } }),
    "PUT /api/findings/triage": (call: ApiCall) => {
      const { checkId, state, reason, expiresAt } = body(call);
      const item = { ...triageRecord(checkId, state, reason, expiresAt), triagedAt: new Date().toISOString() };
      items.set(checkId, item);
      return { json: { item } };
    },
    "DELETE /api/findings/triage": (call: ApiCall) => {
      items.delete(body(call).checkId);
      return { json: { count: 1, items: [] } };
    },
  };
}
