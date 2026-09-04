import { describe, it, expect } from "vitest";
import { scrubSentryEvent } from "./sentryScrub";

describe("scrubSentryEvent", () => {
  it("redacts a target-auth password field", () => {
    const event = { request: { data: { basic_password: "hunter2" } } };
    const scrubbed = scrubSentryEvent(event) as typeof event;
    expect(scrubbed.request.data.basic_password).toBe("[Redacted]");
  });

  it("redacts fields case-insensitively and by substring match", () => {
    const event = { extra: { COOKIE_VALUE: "abc", userApiKey: "xyz", authToken: "def" } };
    const scrubbed = scrubSentryEvent(event) as { extra: Record<string, string> };
    expect(scrubbed.extra.COOKIE_VALUE).toBe("[Redacted]");
    expect(scrubbed.extra.userApiKey).toBe("[Redacted]");
    expect(scrubbed.extra.authToken).toBe("[Redacted]");
  });

  it("leaves non-sensitive fields untouched", () => {
    const event = { extra: { targetUrl: "https://example.com", scanId: "abc-123" } };
    const scrubbed = scrubSentryEvent(event) as { extra: Record<string, string> };
    expect(scrubbed.extra.targetUrl).toBe("https://example.com");
    expect(scrubbed.extra.scanId).toBe("abc-123");
  });

  it("does not scrub scan findings — they're the customer's own security data, not a credential", () => {
    const event = { extra: { findings: [{ severity: "high", title: "Missing HSTS header" }] } };
    const scrubbed = scrubSentryEvent(event) as { extra: { findings: unknown[] } };
    expect(scrubbed.extra.findings).toEqual([{ severity: "high", title: "Missing HSTS header" }]);
  });

  it("scrubs nested objects and arrays recursively", () => {
    const event = { extra: { credentials: [{ basic_username: "admin", basic_password: "secret", targetUrl: "https://example.com" }] } };
    const scrubbed = scrubSentryEvent(event) as {
      extra: { credentials: Array<{ basic_username: string; basic_password: string; targetUrl: string }> };
    };
    // Both basic_username and basic_password are treated as sensitive here
    // (target-auth credentials, sql/migrations/014_target_auth_credentials.sql)
    // — only genuinely unrelated fields on the same nested object survive.
    expect(scrubbed.extra.credentials[0].basic_username).toBe("[Redacted]");
    expect(scrubbed.extra.credentials[0].basic_password).toBe("[Redacted]");
    expect(scrubbed.extra.credentials[0].targetUrl).toBe("https://example.com");
  });

  it("leaves the exception message/stack and other top-level event fields untouched", () => {
    const event = { message: "TypeError: cannot read property 'token' of undefined", level: "error", extra: undefined };
    const scrubbed = scrubSentryEvent(event) as typeof event;
    expect(scrubbed.message).toBe("TypeError: cannot read property 'token' of undefined");
    expect(scrubbed.level).toBe("error");
  });

  it("handles an event with no request/extra/contexts without throwing", () => {
    expect(() => scrubSentryEvent({})).not.toThrow();
  });
});
