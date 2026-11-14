import { describe, it, expect } from "vitest";
import { mayHaveSupabaseSession } from "./sessionHint";

describe("mayHaveSupabaseSession", () => {
  it("is false for a visitor with no session cookie and a plain URL", () => {
    expect(mayHaveSupabaseSession("", "", "")).toBe(false);
    expect(mayHaveSupabaseSession("theme=dark; cookie_consent=declined", "?utm_source=x", "#pricing")).toBe(false);
  });

  it("finds the session cookie, whole or split into chunks, in any position", () => {
    expect(mayHaveSupabaseSession("sb-abc123-auth-token=base64-x", "", "")).toBe(true);
    expect(mayHaveSupabaseSession("theme=dark; sb-abc123-auth-token.0=base64-x", "", "")).toBe(true);
  });

  it("ignores cookies that only look similar", () => {
    expect(mayHaveSupabaseSession("sb-abc123-auth-token-code-verifier=x", "", "")).toBe(false);
    expect(mayHaveSupabaseSession("not-sb-abc123-auth-token=x", "", "")).toBe(false);
  });

  it("is true on a sign-in callback URL, before any cookie exists", () => {
    expect(mayHaveSupabaseSession("", "?code=abc", "")).toBe(true);
    expect(mayHaveSupabaseSession("", "", "#access_token=abc&type=magiclink")).toBe(true);
    expect(mayHaveSupabaseSession("", "", "#error=access_denied&error_description=expired")).toBe(true);
  });
});
