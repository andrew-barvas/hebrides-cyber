import { describe, it, expect, vi } from "vitest";
import { recordLogin, type LoginFields } from "./loginRecorder";

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
