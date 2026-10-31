import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, planGateMock, upsertMock, rowsRef } = vi.hoisted(() => ({
  authMock: vi.fn(),
  planGateMock: vi.fn(),
  upsertMock: vi.fn(),
  rowsRef: { rows: [] as unknown[] },
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authMock,
  supabaseAdmin: {
    from: () => ({
      select: () => ({ eq: () => ({ eq: () => Promise.resolve({ data: rowsRef.rows, error: null }) }) }),
      upsert: upsertMock,
    }),
  },
}));
vi.mock("@/lib/planAccess", () => ({ planGate: planGateMock }));

import handler from "@/pages/api/account/aws-role-credential";
import { decryptCredentials } from "@/lib/credentialEncryption";

async function call(method: "GET" | "POST", body?: unknown) {
  const { req, res } = createMocks({ method, body: body as never });
  await handler(req as unknown as NextApiRequest, res as unknown as NextApiResponse);
  return { status: res._getStatusCode(), json: res._getData() ? JSON.parse(res._getData()) : null };
}

describe("/api/account/aws-role-credential", () => {
  beforeEach(() => {
    authMock.mockReset();
    planGateMock.mockReset();
    upsertMock.mockReset();
    authMock.mockResolvedValue({ via: "session", ownerId: "o1" });
    planGateMock.mockResolvedValue("ok");
    upsertMock.mockResolvedValue({ error: null });
    rowsRef.rows = [];
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
  });

  it("rejects below the Agency tier", async () => {
    planGateMock.mockResolvedValue("denied");
    expect((await call("POST", { label: "prod" })).status).toBe(403);
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("step 1 generates an external id and stores it encrypted with no role yet", async () => {
    const { status, json } = await call("POST", { label: "prod" });
    expect(status).toBe(200);
    expect(json.externalId).toMatch(/^hc-[0-9a-f]{32}$/);
    const stored = upsertMock.mock.calls[0][0];
    expect(JSON.stringify(stored)).not.toContain(json.externalId);
    expect(decryptCredentials(stored.credentials_encrypted)).toMatchObject({ authMode: "role", externalId: json.externalId, roleArn: "" });
  });

  it("step 2 keeps the same external id when the role ARN is saved", async () => {
    const first = await call("POST", { label: "prod" });
    rowsRef.rows = [{ id: "r1", label: "prod", credentials_encrypted: upsertMock.mock.calls[0][0].credentials_encrypted }];
    const arn = "arn:aws:iam::123456789012:role/HebridesCyberAudit";
    const second = await call("POST", { label: "prod", roleArn: arn });
    expect(second.json.externalId).toBe(first.json.externalId);
    expect(decryptCredentials(upsertMock.mock.calls[1][0].credentials_encrypted).roleArn).toBe(arn);
  });

  it("rejects a role ARN that is not an IAM role", async () => {
    expect((await call("POST", { label: "prod", roleArn: "arn:aws:iam::123456789012:user/bob" })).status).toBe(400);
  });
});
