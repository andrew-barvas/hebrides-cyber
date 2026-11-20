import { describe, it, expect, vi, afterEach } from "vitest";
import { ApiError, apiFetch } from "./_shared";

function answer(status: number, body: string, statusText = "") {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status, statusText, headers: { "content-type": "application/json" } })));
}

async function refusal(): Promise<ApiError> {
  try {
    await apiFetch("/api/x", "t");
  } catch (e) {
    return e as ApiError;
  }
  throw new Error("apiFetch did not throw");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch", () => {
  it("sends the bearer token and returns the parsed body", async () => {
    answer(200, JSON.stringify({ ok: true }));
    expect(await apiFetch("/api/x", "tok")).toEqual({ ok: true });
    const [, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it("throws an ApiError that keeps the route's message and fields", async () => {
    answer(409, JSON.stringify({ error: "The engagement can't move to that state.", reason: "no_emergency_contact" }));
    const e = await refusal();
    expect(e).toBeInstanceOf(ApiError);
    expect(e.message).toBe("The engagement can't move to that state.");
    expect(e.status).toBe(409);
    expect(e.body.reason).toBe("no_emergency_contact");
  });

  it("still throws an ApiError for a body that is null, an array or not JSON", async () => {
    for (const [body, text] of [["null", "Bad Gateway"], ["[1]", ""], ["<html>", "Service Unavailable"]] as const) {
      answer(502, body, text);
      const e = await refusal();
      expect(e, body).toBeInstanceOf(ApiError);
      expect(e.message, body).toBe(text || "HTTP 502");
      expect(e.body, body).toEqual({});
    }
  });
});
