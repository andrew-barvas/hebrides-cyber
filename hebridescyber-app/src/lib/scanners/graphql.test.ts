import { describe, it, expect, vi, afterEach } from "vitest";
import { buildGraphqlFindings, checkGraphql, hasSuggestionLeak, introspectionTypeCount, isGraphqlResponse, type GraphqlResult } from "./graphql";
import { summariseResults, type ScanResults } from "./index";
import { getComplianceRefs } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";

afterEach(() => vi.unstubAllGlobals());

describe("response recognisers", () => {
  it("accepts GraphQL's own answers and nothing else", () => {
    expect(isGraphqlResponse({ data: { __typename: "Query" } })).toBe(true);
    expect(isGraphqlResponse({ errors: [{ message: 'Cannot query field "x" on type "Query".' }] })).toBe(true);
    expect(isGraphqlResponse({ errors: [{ message: "GraphQL operations must contain a non-empty `query`" }] })).toBe(true);
    // A catch-all that merely echoes "data", or an ordinary API error, is not GraphQL.
    expect(isGraphqlResponse({ data: { items: [] } })).toBe(false);
    expect(isGraphqlResponse({ data: "x" })).toBe(false);
    expect(isGraphqlResponse({ errors: [{ message: "Not found" }] })).toBe(false);
    expect(isGraphqlResponse({ errors: [null, { code: 1 }] })).toBe(false);
    expect(isGraphqlResponse({ errors: "boom" })).toBe(false);
    expect(isGraphqlResponse(null)).toBe(false);
  });

  it("reads introspection and suggestions", () => {
    expect(introspectionTypeCount({ data: { __schema: { types: [{ name: "A" }, { name: "B" }] } } })).toBe(2);
    expect(introspectionTypeCount({ data: { __schema: {} } })).toBeNull();
    expect(introspectionTypeCount({ errors: [] })).toBeNull();
    expect(introspectionTypeCount(null)).toBeNull();
    expect(hasSuggestionLeak({ errors: [{ message: 'Cannot query field "__typenam". Did you mean "__typename"?' }] })).toBe(true);
    expect(hasSuggestionLeak({ errors: [{ message: "Cannot query field" }] })).toBe(false);
    expect(hasSuggestionLeak(null)).toBe(false);
  });
});

type Handler = (url: URL, init?: RequestInit) => Response | Promise<Response>;
function stub(handler: Handler) {
  const calls: { url: string; method: string; body: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      calls.push({ url: url.pathname, method: init?.method ?? "GET", body: String(init?.body ?? "") });
      return handler(url, init);
    })
  );
  return calls;
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const html = (body: string, status = 200) => new Response(body, { status, headers: { "content-type": "text/html" } });

/** A GraphQL server at /graphql: introspection open or not, suggestions on or off, optional IDE. */
function graphqlServer(opts: { introspection: boolean; suggestions?: boolean; ide?: string }): Handler {
  return (url, init) => {
    if (url.pathname === "/graphql" && init?.method === "POST") {
      const body = String(init.body);
      if (body.includes("__schema")) return opts.introspection ? json({ data: { __schema: { types: [{ name: "Query" }, { name: "User" }] } } }) : json({ errors: [{ message: "GraphQL introspection is not allowed" }] });
      if (body.includes("__typenam }")) return json({ errors: [{ message: opts.suggestions ? 'Cannot query field "__typenam". Did you mean "__typename"?' : 'Cannot query field "__typenam".' }] }, 400);
      return json({ data: { __typename: "Query" } });
    }
    if (opts.ide && url.pathname === "/graphiql") return html(opts.ide);
    return html("not found", 404);
  };
}

describe("checkGraphql", () => {
  it("reports open introspection with the type count, and probes only with read-only queries", async () => {
    const calls = stub(graphqlServer({ introspection: true }));
    const r = await checkGraphql("https://x.test/some/page");
    expect(r).toEqual({ status: "checked", endpoints: [{ path: "/graphql", introspection: { open: true, typeCount: 2 }, suggestionsLeak: false }], ides: [] });
    for (const c of calls.filter((x) => x.method === "POST")) expect(c.body).not.toMatch(/mutation/i);
  });

  it("notes suggestion leakage only when introspection is off", async () => {
    stub(graphqlServer({ introspection: false, suggestions: true }));
    expect(await checkGraphql("https://x.test/")).toMatchObject({ endpoints: [{ introspection: { open: false, typeCount: 0 }, suggestionsLeak: true }] });
    stub(graphqlServer({ introspection: false, suggestions: false }));
    expect(await checkGraphql("https://x.test/")).toMatchObject({ endpoints: [{ suggestionsLeak: false }] });
  });

  it("treats a JSON array or non-JSON body as not GraphQL, and survives a failed schema probe", async () => {
    stub(() => new Response("[1,2]", { headers: { "content-type": "application/json" } }));
    expect(await checkGraphql("https://x.test/")).toEqual({ status: "not_applicable" });
    stub((url, init) => {
      const body = String(init?.body ?? "");
      if (url.pathname === "/graphql" && body.includes("__schema")) throw new Error("reset");
      if (url.pathname === "/graphql" && init?.method === "POST") return body.includes("__typenam }") ? json({ errors: [{ message: "Cannot query field" }] }) : json({ data: { __typename: "Query" } });
      return html("x", 404);
    });
    expect(await checkGraphql("https://x.test/")).toMatchObject({ endpoints: [{ introspection: { open: false } }] });
  });

  it("does not look for suggestions when the typo probe fails", async () => {
    stub((url, init) => {
      if (url.pathname === "/graphql" && init?.method === "POST") {
        const body = String(init.body);
        if (body.includes("__typenam }")) throw new Error("reset");
        if (body.includes("__schema")) return json({ errors: [{ message: "GraphQL introspection is not allowed" }] });
        return json({ data: { __typename: "Query" } });
      }
      return html("x", 404);
    });
    expect(await checkGraphql("https://x.test/")).toMatchObject({ endpoints: [{ suggestionsLeak: false }] });
  });

  it("finds an IDE by its own page text, not by a 200, and de-duplicates", async () => {
    stub((url, init) => {
      if (init?.method === "POST") return graphqlServer({ introspection: false })(url, init);
      if (url.pathname === "/graphiql" || url.pathname === "/graphql") return html("<title>GraphiQL</title>");
      if (url.pathname === "/playground") return html("<h1>Welcome</h1>"); // 200 but no IDE text
      return html("nope", 404);
    });
    expect(await checkGraphql("https://x.test/")).toMatchObject({ ides: ["/graphiql", "/graphql"] });
  });

  it("is not_applicable for a catch-all that answers every POST (the false-positive trap)", async () => {
    stub((url) => (url.pathname === "/" ? html("<html></html>") : json({ data: { items: [1, 2] } })));
    expect(await checkGraphql("https://x.test/")).toEqual({ status: "not_applicable" });
    stub(() => html("<html>app shell</html>"));
    expect(await checkGraphql("https://x.test/")).toEqual({ status: "not_applicable" });
  });

  it("is an error, not 'no GraphQL', when the site cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect(await checkGraphql("https://x.test/")).toMatchObject({ status: "error" });
    expect(await checkGraphql("not a url")).toMatchObject({ status: "error", note: expect.stringMatching(/valid web address/) });
  });

  it("ignores an IDE page fetch that fails or returns non-200", async () => {
    stub((url, init) => {
      if (init?.method === "POST") return graphqlServer({ introspection: true })(url, init);
      if (url.pathname === "/graphiql") throw new Error("reset");
      return html("GraphiQL", 403);
    });
    expect(await checkGraphql("https://x.test/")).toMatchObject({ ides: [] });
  });
});

describe("buildGraphqlFindings", () => {
  const ep = (over: Partial<GraphqlResult & { status: "checked" }> = {}): GraphqlResult => ({ status: "checked", endpoints: [], ides: [], ...over });

  it("turns each exposure into a finding with a stable checkId, remediation, compliance and effort", () => {
    const findings = buildGraphqlFindings(ep({
      endpoints: [
        { path: "/graphql", introspection: { open: true, typeCount: 12 }, suggestionsLeak: true },
        { path: "/api/graphql", introspection: { open: false, typeCount: 0 }, suggestionsLeak: true },
        { path: "/gql", introspection: { open: false, typeCount: 0 }, suggestionsLeak: false },
      ],
      ides: ["/graphiql"],
    }));
    expect(findings.map((f) => f.checkId)).toEqual(["graphql.introspection:/graphql", "graphql.suggestions:/api/graphql", "graphql.ide:/graphiql"]);
    expect(findings[0]).toMatchObject({ severity: "medium", remediation: expect.stringContaining("introspection") });
    expect(findings[0].detail).toContain("12 types");
    for (const f of findings) {
      expect(f.remediation).toBeTruthy();
      expect(getComplianceRefs(f.checkId).length).toBeGreaterThan(0);
      expect(getFixDifficulty(f.checkId)).toBeTruthy();
    }
  });

  it("reports nothing for a check that did not find or run", () => {
    expect(buildGraphqlFindings(undefined)).toEqual([]);
    expect(buildGraphqlFindings({ status: "not_applicable" })).toEqual([]);
    expect(buildGraphqlFindings({ status: "error", note: "x" })).toEqual([]);
  });

  it("flows through summariseResults", () => {
    const err = { status: "error", note: "x" };
    const results = {
      target_url: "https://x.test", checked_at: "2026-10-05T00:00:00Z",
      tls: err, headers: err, dns: err, exposure: err, directoryListing: err, cloudMisconfig: err, fingerprint: err, ports: err,
      playwright: err, recon: err, webapp: err, safeBrowsing: err, waybackDiscovery: err, hibp: err, wpVulnDb: err, softwareCveDb: err,
      businessLogic: err, apiSpec: err, zap: err, backendExposure: err,
      graphql: { status: "checked", endpoints: [{ path: "/graphql", introspection: { open: true, typeCount: 3 }, suggestionsLeak: false }], ides: [] },
    } as unknown as ScanResults;
    expect(summariseResults(results).findings.some((f) => f.checkId === "graphql.introspection:/graphql")).toBe(true);
  });
});
