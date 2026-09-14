import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runGraphqlChecks } from "./graphql";

describe("runGraphqlChecks", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns not_applicable when no GraphQL endpoints found", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("not found")));
    const result = await runGraphqlChecks("https://example.com");
    expect(result.status).toBe("not_applicable");
  });

  it("detects introspection enabled", async () => {
    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (typeof url === "string" && url.includes("/graphql")) {
        return {
          ok: true,
          text: async () => JSON.stringify({
            data: { __schema: { types: [{ name: "Query" }] } },
          }),
        };
      }
      throw new Error("not found");
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await runGraphqlChecks("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.endpoints).toContain("/graphql");
      expect(result.findings.some((f) => f.checkId?.startsWith("graphql.introspection"))).toBe(true);
    }
  });

  it("detects unauthenticated access", async () => {
    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (typeof url === "string" && url.includes("/graphql")) {
        return {
          ok: true,
          text: async () => JSON.stringify({ data: { __typename: "Query" } }),
        };
      }
      throw new Error("not found");
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await runGraphqlChecks("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings.some((f) => f.checkId?.startsWith("graphql.no-auth"))).toBe(true);
    }
  });

  it("handles fetch errors gracefully", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
    const result = await runGraphqlChecks("https://example.com");
    expect(result.status).toBe("not_applicable");
  });
});
