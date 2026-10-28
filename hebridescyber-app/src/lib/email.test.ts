import { describe, it, expect, vi, afterEach } from "vitest";
import { sendEmail } from "./email";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function stubResend() {
  vi.stubEnv("RESEND_API_KEY", "re_test");
  // No service-role env, so recordOutcome() no-ops.
  vi.stubEnv("SUPABASE_URL", "");
  const fetchMock = vi.fn<(url: string, init: RequestInit) => Promise<Response>>(async () => new Response("{}", { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const bodyOf = (fetchMock: ReturnType<typeof stubResend>) => JSON.parse(fetchMock.mock.calls[0][1].body as string);

describe("sendEmail", () => {
  it("sends attachments base64-encoded, as Resend's JSON API expects", async () => {
    const fetchMock = stubResend();
    const result = await sendEmail({
      to: "a@example.com",
      subject: "S",
      html: "<p>h</p>",
      attachments: [{ filename: "report.pdf", content: Buffer.from("%PDF-1.7") }],
    });

    expect(result).toEqual({ ok: true });
    expect(bodyOf(fetchMock).attachments).toEqual([{ filename: "report.pdf", content: Buffer.from("%PDF-1.7").toString("base64") }]);
  });

  it("leaves the attachments field out when there are none", async () => {
    const fetchMock = stubResend();
    await sendEmail({ to: ["a@example.com"], subject: "S", html: "<p>h</p>", attachments: [] });

    const body = bodyOf(fetchMock);
    expect(body).not.toHaveProperty("attachments");
    expect(body.to).toEqual(["a@example.com"]);
  });

  it("does not attempt a send without RESEND_API_KEY", async () => {
    vi.stubEnv("RESEND_API_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    expect(await sendEmail({ to: "a@example.com", subject: "S", html: "h" })).toEqual({ ok: false, error: "RESEND_API_KEY not configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
