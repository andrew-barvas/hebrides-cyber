import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, validatePagerDutyKeyMock, validateOpsgenieKeyMock, upsertMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  validatePagerDutyKeyMock: vi.fn(),
  validateOpsgenieKeyMock: vi.fn(),
  upsertMock: vi.fn(),
}));

vi.mock("@/lib/oncallIntegrations", () => ({
  validatePagerDutyKey: validatePagerDutyKeyMock,
  validateOpsgenieKey: validateOpsgenieKeyMock,
}));
vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authMock,
  supabaseAdmin: {
    from: () => {
      const b: Record<string, unknown> = {};
      b.upsert = (row: unknown, opts: unknown) => upsertMock(row, opts);
      b.delete = () => b;
      b.eq = () => b;
      b.then = (resolve: (v: unknown) => void) => resolve({ error: null });
      return b;
    },
  },
}));

import handler from "@/pages/api/account/oncall-integration";
import { decryptSecret, isEncryptedSecret } from "@/lib/credentialEncryption";

const TEST_KEY = Buffer.alloc(32, 7).toString("base64");

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

describe("POST /api/account/oncall-integration — keys stored encrypted", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
    authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    validatePagerDutyKeyMock.mockReset().mockResolvedValue({ ok: true });
    validateOpsgenieKeyMock.mockReset().mockResolvedValue({ ok: true });
    upsertMock.mockReset().mockResolvedValue({ error: null });
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  it("encrypts the PagerDuty routing key before saving it", async () => {
    const res = await call("POST", { provider: "pagerduty", routingKey: "pd-PLAIN" });
    expect(res._getStatusCode()).toBe(200);
    const [row] = upsertMock.mock.calls[0] as [Record<string, string>];
    expect(row).toMatchObject({ owner: "owner-1", provider: "pagerduty" });
    expect(isEncryptedSecret(row.pagerduty_routing_key)).toBe(true);
    expect(decryptSecret(row.pagerduty_routing_key)).toBe("pd-PLAIN");
    expect(JSON.stringify(row)).not.toContain("pd-PLAIN");
  });

  it("encrypts the Opsgenie API key and keeps the region readable", async () => {
    const res = await call("POST", { provider: "opsgenie", apiKey: "og-PLAIN", region: "eu" });
    expect(res._getStatusCode()).toBe(200);
    const [row] = upsertMock.mock.calls[0] as [Record<string, string>];
    expect(row.region).toBe("eu");
    expect(decryptSecret(row.opsgenie_api_key)).toBe("og-PLAIN");
    expect(JSON.stringify(row)).not.toContain("og-PLAIN");
  });

  it.each([
    { provider: "pagerduty", routingKey: "k" },
    { provider: "opsgenie", apiKey: "k", region: "us" },
  ])("503s with nothing saved, and without contacting $provider, when no key is configured", async (body) => {
    delete process.env.CREDENTIALS_ENC_KEY;
    const res = await call("POST", body);
    expect(res._getStatusCode()).toBe(503);
    expect(validatePagerDutyKeyMock).not.toHaveBeenCalled();
    expect(validateOpsgenieKeyMock).not.toHaveBeenCalled();
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("still lets a customer disconnect with no key configured", async () => {
    delete process.env.CREDENTIALS_ENC_KEY;
    expect((await call("DELETE", { provider: "pagerduty" }))._getStatusCode()).toBe(200);
  });

  it("refuses API-key callers", async () => {
    authMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    expect((await call("POST", { provider: "pagerduty", routingKey: "k" }))._getStatusCode()).toBe(403);
  });
});
