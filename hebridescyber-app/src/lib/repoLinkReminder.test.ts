import { describe, expect, it, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import { buildReminderEmail, groupByOwner, sendRepoLinkReminders } from "./repoLinkReminder";

let rows: Array<{ id: string; owner: string; github_repo: string }>;
let marked: Array<{ ids: string[]; row: Record<string, unknown> }>;
const db = () =>
  ({
    from: (table: string) => {
      const q: Record<string, unknown> = {
        select: () => q,
        is: () => q,
        eq: () => q,
        maybeSingle: async () => ({ data: { email: "owner@example.com" }, error: null }),
        update: (row: Record<string, unknown>) => ({ in: async (_c: string, ids: string[]) => (marked.push({ ids, row }), { error: null }) }),
        then: (r: (v: unknown) => void) => r(table === "repo_connections" ? { data: rows, error: null } : { data: null, error: null }),
      };
      return q;
    },
  }) as unknown as SupabaseClient;

beforeEach(() => {
  rows = [
    { id: "1", owner: "o1", github_repo: "acme/site" },
    { id: "2", owner: "o1", github_repo: "acme/api" },
    { id: "3", owner: "o2", github_repo: "beta/<app>" },
  ];
  marked = [];
  sendEmailMock.mockReset().mockResolvedValue({ ok: true });
});

describe("repo link reminders", () => {
  it("groups by owner and escapes repository names", () => {
    expect([...groupByOwner(rows).keys()]).toEqual(["o1", "o2"]);
    const one = buildReminderEmail(["beta/<app>"], "https://www.hebridescyber.co.uk");
    expect(one.subject).toBe("Your repository's code checks are paused: choose its site");
    expect(one.html).toContain("beta/&lt;app&gt;");
    expect(one.html).toContain("https://www.hebridescyber.co.uk/dashboard/integrations#connect-repo");
    expect(buildReminderEmail(["a/b", "c/d"], "x").subject).toContain("choose their sites");
  });

  it("emails each owner once and records every connection it covered", async () => {
    const r = await sendRepoLinkReminders(db(), { now: new Date("2026-11-20T10:00:00Z") });
    expect(r).toEqual({ sent: 2, skipped: 0, errors: [] });
    expect(sendEmailMock).toHaveBeenCalledTimes(2);
    expect(marked).toEqual([
      { ids: ["1", "2"], row: { link_reminder_sent_at: "2026-11-20T10:00:00.000Z" } },
      { ids: ["3"], row: { link_reminder_sent_at: "2026-11-20T10:00:00.000Z" } },
    ]);
  });

  it("a dry run sends and records nothing; a failed send isn't recorded", async () => {
    expect((await sendRepoLinkReminders(db(), { dryRun: true })).skipped).toBe(2);
    expect(sendEmailMock).not.toHaveBeenCalled();
    sendEmailMock.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });
    const r = await sendRepoLinkReminders(db());
    expect(r.errors).toHaveLength(2);
    expect(marked).toEqual([]);
  });
});
