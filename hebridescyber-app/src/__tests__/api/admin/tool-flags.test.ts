import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";
import { EXTENDED_TOOL_NAMES } from "@/lib/scanProfiles";

const { requireAdminMock, logAuditEventMock } = vi.hoisted(() => ({
  requireAdminMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/admin/tool-flags";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    headers: { authorization: "Bearer t" },
    ...overrides,
  });
}

describe("/api/admin/tool-flags", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects unknown methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "DELETE" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("GET lists every known tool, flagging the disabled ones", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      tool_kill_switches: [{ data: [{ tool_name: "nuclei", disabled: true }, { tool_name: "zap", disabled: false }], error: null }],
    });
    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { tools: { tool: string; disabled: boolean }[] };
    expect(body.tools).toHaveLength(EXTENDED_TOOL_NAMES.length);
    expect(body.tools.find((t) => t.tool === "nuclei")).toEqual({ tool: "nuclei", disabled: true });
    expect(body.tools.find((t) => t.tool === "zap")).toEqual({ tool: "zap", disabled: false });
  });

  it("PATCH rejects an unknown tool", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "PATCH", body: { tool: "not_a_tool", disabled: true } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("PATCH rejects a non-boolean disabled", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "PATCH", body: { tool: "nuclei", disabled: "yes" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("PATCH upserts the flag and audits the change", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ tool_kill_switches: [{ data: null, error: null }] });
    const { req, res } = mockReqRes({ method: "PATCH", body: { tool: "sqlmap", disabled: true } });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(mock.upserted).toHaveLength(1);
    expect(mock.upserted[0].table).toBe("tool_kill_switches");
    expect(mock.upserted[0].payload).toMatchObject({ tool_name: "sqlmap", disabled: true, updated_by: "admin-1" });
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ action: "admin.tool_disabled", resourceType: "scan_tool", resourceId: "sqlmap" })
    );
  });

  it("PATCH audits a re-enable with the enabled action", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ tool_kill_switches: [{ data: null, error: null }] });
    const { req, res } = mockReqRes({ method: "PATCH", body: { tool: "sqlmap", disabled: false } });
    await handler(req, res);

    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ action: "admin.tool_enabled", resourceId: "sqlmap" })
    );
  });
});
