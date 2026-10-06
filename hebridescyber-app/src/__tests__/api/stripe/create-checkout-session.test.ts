import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import type { NextApiHandler } from "next";

const { checkoutSessionsCreateMock, getUserMock } = vi.hoisted(() => ({
  checkoutSessionsCreateMock: vi.fn(),
  getUserMock: vi.fn(),
}));

vi.mock("@/lib/stripeClient", () => ({
  getStripe: () => ({ checkout: { sessions: { create: checkoutSessionsCreateMock } } }),
}));

vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: { auth: { getUser: getUserMock } },
}));

function mockReqRes(body: Record<string, unknown>) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "POST",
    headers: { authorization: "Bearer test-token" },
    body,
  });
}

// create-checkout-session.ts reads STRIPE_PRICE_* into a top-level
// PRICE_IDS constant at module load, not per-request. A plain top-level
// `import` hoists above any code in this file regardless of source order
// (an ESM transpilation rule, not something `vi.mock`-style tricks get
// around), so the env var has to be set and the module re-imported inside
// each test via vi.resetModules() + a dynamic import — the only way to
// control what PRICE_IDS actually captures per test.
async function loadHandler(): Promise<NextApiHandler> {
  vi.resetModules();
  const mod = await import("@/pages/api/stripe/create-checkout-session");
  return mod.default;
}

describe("POST /api/stripe/create-checkout-session", () => {
  beforeEach(() => {
    checkoutSessionsCreateMock.mockReset().mockResolvedValue({ url: "https://checkout.stripe.com/session-1" });
    getUserMock.mockReset().mockResolvedValue({
      data: { user: { id: "user-1", email: "owner@example.com" } },
      error: null,
    });
    delete process.env.STRIPE_PRICE_BASIC;
    delete process.env.STRIPE_PRICE_PRO;
    delete process.env.STRIPE_PRICE_AGENCY;
  });

  // Regression test for a real production bug: the created Checkout Session
  // carried `metadata.plan`, but the Stripe Subscription object it spawns
  // did not — webhook.ts's customer.subscription.updated handler reads
  // sub.metadata.plan and falls back to "basic" when it's absent, silently
  // downgrading Pro/Agency customers on their very first renewal or any
  // billing-portal change. subscription_data.metadata is what actually
  // stamps metadata onto the Subscription itself, not just the Session.
  it("stamps plan metadata onto subscription_data so it survives onto the Subscription object", async () => {
    process.env.STRIPE_PRICE_PRO = "price_pro_123";
    const handler = await loadHandler();
    const { req, res } = mockReqRes({ plan: "pro" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(checkoutSessionsCreateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: { plan: "pro" },
        subscription_data: { metadata: { plan: "pro" } },
      })
    );
  });

  it("tells the customer sign-up isn't open when a plan's price isn't configured, and logs which variable is missing", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const handler = await loadHandler();
    const { req, res } = mockReqRes({ plan: "basic" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    const body = JSON.parse(res._getData());
    expect(body.code).toBe("checkout_unavailable");
    expect(body.error).not.toMatch(/STRIPE|environment/);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("STRIPE_PRICE_BASIC"));
    expect(checkoutSessionsCreateMock).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it("returns 400 for a plan that doesn't exist", async () => {
    const handler = await loadHandler();
    for (const plan of [undefined, "enterprise", "__proto__"]) {
      const { req, res } = mockReqRes({ plan });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    }
    expect(checkoutSessionsCreateMock).not.toHaveBeenCalled();
  });

  it("keeps Stripe's own errors and missing keys out of the customer's view", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    process.env.STRIPE_PRICE_PRO = "price_pro_123";
    const handler = await loadHandler();

    checkoutSessionsCreateMock.mockRejectedValueOnce(new Error("STRIPE_SECRET_KEY must be set"));
    const unconfigured = mockReqRes({ plan: "pro" });
    await handler(unconfigured.req, unconfigured.res);
    expect(unconfigured.res._getStatusCode()).toBe(503);
    expect(JSON.parse(unconfigured.res._getData()).code).toBe("checkout_unavailable");

    checkoutSessionsCreateMock.mockRejectedValueOnce(new Error("No such price: 'price_pro_123'"));
    const failed = mockReqRes({ plan: "pro" });
    await handler(failed.req, failed.res);
    expect(failed.res._getStatusCode()).toBe(502);
    expect(JSON.parse(failed.res._getData()).error).not.toMatch(/price_pro_123/);
    log.mockRestore();
  });
});
