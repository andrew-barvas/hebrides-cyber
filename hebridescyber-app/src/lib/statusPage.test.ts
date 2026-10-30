import { describe, it, expect } from "vitest";
import { statusPageUrl } from "./statusPage";

describe("statusPageUrl", () => {
  it("returns a valid https URL", () => {
    expect(statusPageUrl("https://stats.uptimerobot.com/abc123")).toBe("https://stats.uptimerobot.com/abc123");
    expect(statusPageUrl("  https://status.example.com  ")).toBe("https://status.example.com/");
  });

  it("returns null when unset, blank, malformed, not https or without a real host", () => {
    for (const bad of [undefined, "", "   ", "not a url", "http://status.example.com", "javascript:alert(1)", "https://localhost", "ftp://status.example.com"]) {
      expect(statusPageUrl(bad)).toBeNull();
    }
  });
});
