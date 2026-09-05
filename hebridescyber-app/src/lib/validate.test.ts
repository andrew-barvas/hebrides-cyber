import { describe, it, expect, vi } from "vitest";
import { z } from "zod";
import type { NextApiResponse } from "next";
import { parseBody } from "./validate";

function fakeRes() {
  const res: Partial<NextApiResponse> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as NextApiResponse & { status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> };
}

const schema = z.object({ id: z.string().min(1), read: z.boolean() });

describe("parseBody", () => {
  it("returns the parsed value on a valid body", () => {
    const res = fakeRes();
    const result = parseBody(schema, { id: "11111111-1111-1111-1111-111111111111", read: true }, res);

    expect(result).toEqual({ id: "11111111-1111-1111-1111-111111111111", read: true });
    expect(res.status).not.toHaveBeenCalled();
  });

  it("writes a 400 with a field-scoped message and returns null on a missing field", () => {
    const res = fakeRes();
    const result = parseBody(schema, { id: "11111111-1111-1111-1111-111111111111" }, res);

    expect(result).toBeNull();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining("read:") });
  });

  it("writes a 400 and returns null on a malformed field", () => {
    const res = fakeRes();
    const result = parseBody(schema, { id: "abc", read: "yes" }, res);

    expect(result).toBeNull();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining("read:") });
  });

  it("rejects a body that isn't an object at all", () => {
    const res = fakeRes();
    const result = parseBody(schema, null, res);

    expect(result).toBeNull();
    expect(res.status).toHaveBeenCalledWith(400);
  });
});
