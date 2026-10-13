import { describe, it, expect, vi } from "vitest";
import { recipientDomain, recordEmailOutcome, summarizeEmailHealth, type EmailEventRow } from "./emailEvents";

describe("recipientDomain", () => {
  it("extracts the domain of the first recipient, lower-cased", () => {
    expect(recipientDomain("Alice@Example.COM")).toBe("example.com");
    expect(recipientDomain(["a@one.test", "b@two.test"])).toBe("one.test");
  });

  it("returns null for a missing or malformed address", () => {
    expect(recipientDomain("")).toBeNull();
    expect(recipientDomain([])).toBeNull();
    expect(recipientDomain("no-at-sign")).toBeNull();
    expect(recipientDomain("trailing@")).toBeNull();
  });
});

describe("recordEmailOutcome", () => {
  it("inserts a domain-only row and never throws on a DB error", async () => {
    const inserted: unknown[] = [];
    const db = { from: () => ({ insert: async (v: unknown) => { inserted.push(v); return { error: null }; } }) };
    await recordEmailOutcome(db as never, { to: "person@acme.com", subject: "Hi", status: "sent" });
    expect(inserted[0]).toMatchObject({ recipient_domain: "acme.com", subject: "Hi", status: "sent", error: null });
  });

  it("swallows a thrown DB error", async () => {
    const db = { from: () => ({ insert: () => { throw new Error("boom"); } }) };
    await expect(recordEmailOutcome(db as never, { to: "x@y.test", subject: "s", status: "failed", error: "nope" })).resolves.toBeUndefined();
  });

  it("truncates an over-long subject and error", async () => {
    let row: Record<string, unknown> = {};
    const db = { from: () => ({ insert: async (v: Record<string, unknown>) => { row = v; return { error: null }; } }) };
    await recordEmailOutcome(db as never, { to: "x@y.test", subject: "s".repeat(500), status: "failed", error: "e".repeat(900) });
    expect((row.subject as string).length).toBe(300);
    expect((row.error as string).length).toBe(500);
  });
});

describe("summarizeEmailHealth", () => {
  const now = new Date("2026-06-15T12:00:00Z");
  const row = (over: Partial<EmailEventRow>): EmailEventRow => ({
    status: "sent", subject: "s", recipient_domain: "acme.com", error: null, created_at: "2026-06-15T11:00:00Z", ...over,
  });

  it("counts sent/failed in the window and computes the failure rate", () => {
    const h = summarizeEmailHealth(
      [row({ status: "sent" }), row({ status: "failed", error: "550 blocked" }), row({ status: "sent" }), row({ status: "failed", error: "timeout" })],
      now
    );
    expect(h).toMatchObject({ total: 4, sent: 2, failed: 2, failureRatePct: 50 });
    expect(h.recentFailures).toHaveLength(2);
  });

  it("excludes events older than the window", () => {
    const h = summarizeEmailHealth(
      [row({ created_at: "2026-06-15T11:00:00Z" }), row({ created_at: "2026-06-13T11:00:00Z", status: "failed" })],
      now,
      24
    );
    expect(h.total).toBe(1);
    expect(h.failed).toBe(0);
  });

  it("reports a null failure rate (not 0) when nothing was sent in the window", () => {
    expect(summarizeEmailHealth([], now).failureRatePct).toBeNull();
  });

  it("orders recent failures newest-first and caps at 10", () => {
    const many = Array.from({ length: 15 }, (_, i) =>
      row({ status: "failed", created_at: new Date(now.getTime() - i * 60_000).toISOString(), error: `e${i}` })
    );
    const h = summarizeEmailHealth(many, now);
    expect(h.recentFailures).toHaveLength(10);
    expect(h.recentFailures[0].error).toBe("e0"); // newest
  });
});

describe("sendEmail recording (integration with email.ts)", () => {
  it("records a failed outcome when Resend is configured and the send fails", async () => {
    vi.resetModules();
    const recordSpy = vi.fn(async () => {});
    vi.doMock("./emailEvents", async (orig) => ({ ...(await orig<typeof import("./emailEvents")>()), recordEmailOutcome: recordSpy }));
    vi.stubEnv("RESEND_API_KEY", "re_test");
    vi.stubEnv("SUPABASE_URL", "https://x.supabase.co");
    vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "svc");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("bad", { status: 500 })));

    const { sendEmail } = await import("./email");
    const result = await sendEmail({ to: "p@acme.com", subject: "S", html: "<p>h</p>" });

    expect(result.ok).toBe(false);
    expect(recordSpy).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ status: "failed", to: "p@acme.com" }));

    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.doUnmock("./emailEvents");
    vi.resetModules();
  });
});
