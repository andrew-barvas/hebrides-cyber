import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import type Stripe from "stripe";

const { constructEventMock, subscriptionsRetrieveMock } = vi.hoisted(() => ({
  constructEventMock: vi.fn(),
  subscriptionsRetrieveMock: vi.fn(),
}));

vi.mock("@/lib/stripeClient", () => ({
  getStripe: () => ({
    webhooks: { constructEvent: constructEventMock },
    subscriptions: { retrieve: subscriptionsRetrieveMock },
  }),
}));

// Same call-order-queue pattern as run-scan.test.ts: each table's calls are
// resolved from a queue consumed in call order, and every chain method both
// returns the builder (for further chaining) and resolves via .then (for
// calls awaited without a .single()/.maybeSingle() terminal, e.g. .upsert()
// and bare .update().eq()).
type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
const insertedAuditLogs: unknown[] = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    upsert: () => builder,
    update: () => builder,
    insert: (payload: unknown) => {
      if (table === "audit_logs") insertedAuditLogs.push(payload);
      return builder;
    },
    single: next,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/stripe/webhook";

function mockReqRes() {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "POST",
    headers: { "stripe-signature": "t=1,v1=fake" },
  });
}

function stripeEvent(id: string, type: string, object: Record<string, unknown>): Stripe.Event {
  return { id, type, data: { object } } as unknown as Stripe.Event;
}

// webhook.ts reads the raw body via `await buffer(req)` (bodyParser is
// disabled — Stripe signatures are computed over the exact raw bytes).
// node-mocks-http's req is a real Readable; buffer() attaches its listeners
// synchronously up to that first await, so invoking the handler THEN
// immediately calling req.send() — before awaiting the handler's promise —
// delivers the body to the already-listening stream. The body's actual
// content is irrelevant here since constructEvent() is mocked and ignores
// it; only the request needing to end its stream matters.
async function callHandler(req: NextApiRequest, res: NextApiResponse) {
  const pending = handler(req, res);
  (req as unknown as { send: (data: unknown) => void }).send("{}");
  await pending;
}

describe("POST /api/stripe/webhook", () => {
  beforeEach(() => {
    queues = {};
    insertedAuditLogs.length = 0;
    constructEventMock.mockReset();
    subscriptionsRetrieveMock.mockReset();
    process.env.STRIPE_WEBHOOK_SECRET = "whsec_test";
    delete process.env.SENDGRID_API_KEY;
  });

  afterEach(() => {
    delete process.env.STRIPE_WEBHOOK_SECRET;
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await callHandler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 400 when the webhook secret is not configured", async () => {
    delete process.env.STRIPE_WEBHOOK_SECRET;
    const { req, res } = mockReqRes();
    await callHandler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 400 when signature verification throws", async () => {
    constructEventMock.mockImplementation(() => {
      throw new Error("signature mismatch");
    });
    const { req, res } = mockReqRes();
    await callHandler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(res._getData()).toContain("signature mismatch");
  });

  it("skips an already-processed event without touching subscriptions", async () => {
    constructEventMock.mockReturnValue(stripeEvent("evt_1", "customer.subscription.deleted", { id: "sub_1" }));
    queues.audit_logs = [{ data: { id: "existing-log-row" } }]; // isAlreadyProcessed's lookup finds a row
    const { req, res } = mockReqRes();

    await callHandler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ received: true, skipped: true });
    expect(insertedAuditLogs).toHaveLength(0);
  });

  describe("checkout.session.completed", () => {
    it("does nothing (but still 200s) when client_reference_id is missing", async () => {
      constructEventMock.mockReturnValue(
        stripeEvent("evt_2", "checkout.session.completed", { client_reference_id: null, metadata: { plan: "pro" } })
      );
      queues.audit_logs = [{ data: null }]; // not already processed
      const { req, res } = mockReqRes();

      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(insertedAuditLogs).toHaveLength(0);
    });

    it("activates the subscription, mirrors the Stripe customer id, and sends the welcome email once", async () => {
      constructEventMock.mockReturnValue(
        stripeEvent("evt_3", "checkout.session.completed", {
          client_reference_id: "owner-1",
          metadata: { plan: "pro" },
          subscription: "sub_123",
          customer: "cus_123",
        })
      );
      subscriptionsRetrieveMock.mockResolvedValue({ current_period_end: 1_700_000_000 });
      queues.audit_logs = [{ data: null }]; // not already processed
      // Two separate .from("users") calls happen here: the stripe_customer_id
      // mirror update (result unused), then the select for the welcome-email
      // decision — each consumes its own queue slot in call order.
      queues.users = [{}, { data: { email: "owner@example.com", onboarding_email_sent: false } }];
      process.env.SENDGRID_API_KEY = "SG.test";
      const fetchMock = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", fetchMock);

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(subscriptionsRetrieveMock).toHaveBeenCalledWith("sub_123");
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(String(fetchMock.mock.calls[0][1].body)).toContain("Pro Plan");
      expect(insertedAuditLogs).toHaveLength(1);
      expect(insertedAuditLogs[0]).toMatchObject({ action: "stripe.checkout.completed", actor: "owner-1" });

      vi.unstubAllGlobals();
    });

    it("does not send a duplicate welcome email when onboarding_email_sent is already true", async () => {
      constructEventMock.mockReturnValue(
        stripeEvent("evt_4", "checkout.session.completed", { client_reference_id: "owner-1", metadata: { plan: "basic" } })
      );
      queues.audit_logs = [{ data: null }];
      queues.users = [{ data: { email: "owner@example.com", onboarding_email_sent: true } }];
      process.env.SENDGRID_API_KEY = "SG.test";
      const fetchMock = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", fetchMock);

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(fetchMock).not.toHaveBeenCalled();

      vi.unstubAllGlobals();
    });
  });

  describe("customer.subscription.updated", () => {
    it.each([
      ["active", "active"],
      ["past_due", "past_due"],
      ["canceled", "cancelled"],
      ["paused", "inactive"],
    ] as const)("maps Stripe status %s to our status %s", async (stripeStatus, ourStatus) => {
      constructEventMock.mockReturnValue(
        stripeEvent("evt_5", "customer.subscription.updated", {
          id: "sub_1",
          status: stripeStatus,
          current_period_end: 1_700_000_000,
          metadata: { plan: "agency" },
        })
      );
      queues.audit_logs = [{ data: null }];
      queues.subscriptions = [{ data: { owner: "owner-1" } }];
      queues.users = [{ data: { email: "owner@example.com" } }];

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(insertedAuditLogs[0]).toMatchObject({
        action: "stripe.subscription.updated",
        metadata: { plan: "agency", status: ourStatus },
      });
    });
  });

  describe("invoice.payment_failed", () => {
    it("does nothing when the invoice has no subscription id", async () => {
      constructEventMock.mockReturnValue(stripeEvent("evt_6", "invoice.payment_failed", { subscription: null }));
      queues.audit_logs = [{ data: null }];

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(insertedAuditLogs).toHaveLength(0);
    });

    it("marks the subscription past_due", async () => {
      constructEventMock.mockReturnValue(stripeEvent("evt_7", "invoice.payment_failed", { subscription: "sub_1" }));
      queues.audit_logs = [{ data: null }];
      queues.subscriptions = [{ data: { owner: "owner-1" } }];
      queues.users = [{ data: { email: "owner@example.com" } }];

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(insertedAuditLogs[0]).toMatchObject({ action: "stripe.payment_failed" });
    });
  });

  describe("customer.subscription.deleted", () => {
    it("marks the subscription cancelled", async () => {
      constructEventMock.mockReturnValue(stripeEvent("evt_8", "customer.subscription.deleted", { id: "sub_1" }));
      queues.audit_logs = [{ data: null }];
      queues.subscriptions = [{ data: { owner: "owner-1" } }];
      queues.users = [{ data: { email: "owner@example.com" } }];

      const { req, res } = mockReqRes();
      await callHandler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(insertedAuditLogs[0]).toMatchObject({ action: "stripe.subscription.deleted" });
    });
  });

  it("acknowledges an unhandled event type with 200 and no writes", async () => {
    constructEventMock.mockReturnValue(stripeEvent("evt_9", "customer.updated", {}));
    queues.audit_logs = [{ data: null }];

    const { req, res } = mockReqRes();
    await callHandler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(insertedAuditLogs).toHaveLength(0);
  });

  it("returns 500 without throwing when processing fails mid-event", async () => {
    constructEventMock.mockReturnValue(
      stripeEvent("evt_10", "checkout.session.completed", { client_reference_id: "owner-1", metadata: { plan: "pro" }, subscription: "sub_1" })
    );
    queues.audit_logs = [{ data: null }];
    subscriptionsRetrieveMock.mockRejectedValue(new Error("Stripe API unreachable"));

    const { req, res } = mockReqRes();
    await callHandler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });
});
