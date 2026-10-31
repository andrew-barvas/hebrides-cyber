import { describe, it, expect, vi } from "vitest";
import { recordLogin, driveLogin, type LoginFields } from "./loginRecorder";

const fields = (over: Partial<LoginFields> = {}): LoginFields => ({
  loginUrl: "https://app.example.com/login",
  username: "test-account",
  password: "s3cret",
  ...over,
});

describe("recordLogin", () => {
  it("rejects an invalid URL without calling the runner", async () => {
    const run = vi.fn();
    expect(await recordLogin(fields({ loginUrl: "https://[bad" }), run)).toMatchObject({ status: "error" });
    expect(run).not.toHaveBeenCalled();
  });

  it("rejects a non-https URL — the password would travel unencrypted", async () => {
    const run = vi.fn();
    expect(await recordLogin(fields({ loginUrl: "http://app.example.com/login" }), run)).toMatchObject({
      status: "error",
      note: expect.stringMatching(/https/),
    });
    expect(run).not.toHaveBeenCalled();
  });

  it("rejects a missing username or password without calling the runner", async () => {
    const run = vi.fn();
    expect(await recordLogin(fields({ username: "" }), run)).toMatchObject({ status: "error" });
    expect(await recordLogin(fields({ password: "" }), run)).toMatchObject({ status: "error" });
    expect(run).not.toHaveBeenCalled();
  });

  it("joins the resulting cookies into one Cookie-header-shaped string on success", async () => {
    const run = vi.fn(async () => ({
      success: true,
      cookies: [{ name: "session", value: "abc123" }, { name: "csrf", value: "xyz" }],
    }));
    const result = await recordLogin(fields(), run);
    expect(result).toEqual({ status: "recorded", cookieValue: "session=abc123; csrf=xyz" });
  });

  it("passes the fields through to the runner unchanged, selectors included", async () => {
    const run = vi.fn(async () => ({ success: true, cookies: [{ name: "s", value: "1" }] }));
    const f = fields({ usernameSelector: "#u", passwordSelector: "#p" });
    await recordLogin(f, run);
    expect(run).toHaveBeenCalledWith(f);
  });

  it("is an error when the runner reports the login did not succeed", async () => {
    const run = vi.fn(async () => ({ success: false, cookies: [] }));
    expect(await recordLogin(fields(), run)).toMatchObject({ status: "error", note: expect.stringMatching(/did not appear to succeed/) });
  });

  it("is an error when login 'succeeds' but leaves no cookies to save", async () => {
    const run = vi.fn(async () => ({ success: true, cookies: [] }));
    expect(await recordLogin(fields(), run)).toMatchObject({ status: "error", note: expect.stringMatching(/no cookies/) });
  });

  it("is an error, not a throw, when the runner itself throws", async () => {
    const run = vi.fn(async () => {
      throw new Error("Timeout 10000ms exceeded.");
    });
    expect(await recordLogin(fields(), run)).toMatchObject({ status: "error", note: expect.stringMatching(/Timeout 10000ms exceeded/) });
  });
});

describe("playwrightLoginRun", () => {
  it("fills both fields, presses Enter on the password field, and reads back cookies — closing the browser after", async () => {
    vi.resetModules();
    const close = vi.fn(async () => undefined);
    const fillCalls: Array<{ selector: string; value: string }> = [];
    const press = vi.fn(async () => undefined);
    const isVisible = vi.fn(async () => false);
    const cookies = vi.fn(async () => [{ name: "session", value: "abc" }, { name: "other", value: "x", extraField: "ignored" }]);
    // Each locator() call gets its OWN closure over `sel` — the real code
    // creates both locators before filling either, so a mock that wrote `sel`
    // to one shared outer variable would have both fills see the last one.
    const locator = (sel: string) => ({
      first: () => ({
        fill: vi.fn(async (value: string) => {
          fillCalls.push({ selector: sel, value });
        }),
        press,
        isVisible,
      }),
    });
    const page = { goto: vi.fn(async () => undefined), waitForLoadState: vi.fn(async () => undefined), locator };
    const context = { newPage: vi.fn(async () => page), cookies };
    const browser = { newContext: vi.fn(async () => context), close };

    vi.doMock("playwright", () => ({ chromium: { launch: vi.fn(async () => browser) } }));
    const { playwrightLoginRun } = await import("./loginRecorder");

    const result = await playwrightLoginRun({
      loginUrl: "https://app.example.com/login",
      username: "test-account",
      password: "s3cret",
    });

    expect(fillCalls).toEqual(
      expect.arrayContaining([
        { selector: expect.stringContaining('input[type="email"]'), value: "test-account" },
        { selector: 'input[type="password"]', value: "s3cret" },
      ])
    );
    expect(press).toHaveBeenCalledWith("Enter");
    expect(result).toEqual({ success: true, cookies: [{ name: "session", value: "abc" }, { name: "other", value: "x" }] });
    expect(close).toHaveBeenCalled();
    vi.doUnmock("playwright");
  });

  it("reports failure when a password field is still visible after submitting", async () => {
    vi.resetModules();
    const isVisible = vi.fn(async () => true);
    const locator = () => ({ first: () => ({ fill: vi.fn(async () => undefined), press: vi.fn(async () => undefined), isVisible }) });
    const page = { goto: vi.fn(async () => undefined), waitForLoadState: vi.fn(async () => undefined), locator };
    const context = { newPage: vi.fn(async () => page), cookies: vi.fn(async () => []) };
    const browser = { newContext: vi.fn(async () => context), close: vi.fn(async () => undefined) };
    vi.doMock("playwright", () => ({ chromium: { launch: vi.fn(async () => browser) } }));
    const { playwrightLoginRun } = await import("./loginRecorder");

    const result = await playwrightLoginRun({ loginUrl: "https://app.example.com/login", username: "u", password: "p" });
    expect(result.success).toBe(false);
    vi.doUnmock("playwright");
  });
});

describe("recordLogin with a TOTP secret", () => {
  const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  it("rejects an invalid secret without calling the runner", async () => {
    const run = vi.fn();
    expect(await recordLogin(fields({ totpSecret: "nope!" }), run)).toMatchObject({ status: "error", note: expect.stringMatching(/TOTP secret/) });
    expect(run).not.toHaveBeenCalled();
  });

  it("hands the runner a code supplier, never the secret", async () => {
    const run = vi.fn(async (_f: unknown) => ({ success: true, cookies: [{ name: "s", value: "1" }] }));
    await recordLogin(fields({ totpSecret: SECRET }), run);
    const given = run.mock.calls[0][0] as { mfa: { code: () => string }; totpSecret?: string };
    expect(JSON.stringify(given)).not.toContain(SECRET);
    expect(given.totpSecret).toBeUndefined();
    expect(given.mfa.code()).toMatch(/^\d{6}$/);
  });

  it("is an error, never a recorded session, when the MFA step fails; the note holds no secret", async () => {
    const run = vi.fn(async () => ({ success: false, cookies: [], failedAt: "mfa" as const }));
    const result = await recordLogin(fields({ totpSecret: SECRET }), run);
    expect(result).toMatchObject({ status: "error", note: expect.stringMatching(/MFA step did not complete/) });
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });
});

describe("driveLogin step ordering", () => {
  function fakePage(opts: { mfaShown: boolean; mfaStays?: boolean; passwordStays?: boolean }) {
    const calls: string[] = [];
    const name = (sel: string) => (sel === "#mfa" ? "mfa" : sel === "#p" ? "password" : "username");
    const page = {
      goto: async () => void calls.push("goto"),
      fill: async (sel: string, v: string) => void calls.push(`fill:${name(sel)}:${sel === "#mfa" ? v : ""}`),
      pressEnterAndSettle: async (sel: string) => void calls.push(`submit:${sel}`),
      isVisible: async (sel: string) => (sel === "#mfa" ? !!opts.mfaStays : !!opts.passwordStays),
      waitForVisible: async () => (calls.push("waitMfa"), opts.mfaShown),
      cookies: async () => [{ name: "s", value: "1" }],
    };
    return { page, calls };
  }
  const base = { loginUrl: "https://a.example.com/login", username: "u", password: "p", usernameSelector: "#u", passwordSelector: "#p", mfaSelector: "#mfa" };
  const mfa = { code: () => "123456", msUntilRollover: () => 20_000 };

  it("types the code only after the password is submitted and the MFA field is visible", async () => {
    const { page, calls } = fakePage({ mfaShown: true });
    const out = await driveLogin(page, { ...base, mfa });
    expect(calls).toEqual(["goto", "fill:username:", "fill:password:", "submit:#p", "waitMfa", "fill:mfa:123456", "submit:#mfa"]);
    expect(out).toEqual({ success: true, cookies: [{ name: "s", value: "1" }] });
  });

  it("skips the MFA step when no secret was supplied", async () => {
    const { page, calls } = fakePage({ mfaShown: true });
    await driveLogin(page, base);
    expect(calls).not.toContain("waitMfa");
  });

  it("types no code if the MFA field never appears, and still checks the password field", async () => {
    const { page, calls } = fakePage({ mfaShown: false, passwordStays: true });
    const out = await driveLogin(page, { ...base, mfa });
    expect(calls.some((c) => c.startsWith("fill:mfa"))).toBe(false);
    expect(out).toMatchObject({ success: false, failedAt: "mfa" });
  });

  it("fails at mfa when the field is still there after submitting the code", async () => {
    const { page } = fakePage({ mfaShown: true, mfaStays: true });
    expect(await driveLogin(page, { ...base, mfa })).toMatchObject({ success: false, cookies: [], failedAt: "mfa" });
  });

  it("waits out a code about to roll over before generating it", async () => {
    const { page, calls } = fakePage({ mfaShown: true });
    const sleep = vi.fn(async (_ms: number) => void calls.push("sleep"));
    await driveLogin(page, { ...base, mfa: { code: () => "123456", msUntilRollover: () => 500 } }, sleep);
    expect(sleep).toHaveBeenCalledWith(600);
    expect(calls.indexOf("sleep")).toBeLessThan(calls.indexOf("fill:mfa:123456"));
  });

  it("reports a plain login failure when there is no MFA and the password field remains", async () => {
    const { page } = fakePage({ mfaShown: false, passwordStays: true });
    expect(await driveLogin(page, base)).toMatchObject({ success: false, failedAt: "login" });
  });
});
