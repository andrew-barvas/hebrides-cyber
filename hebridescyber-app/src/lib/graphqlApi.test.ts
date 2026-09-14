import { describe, it, expect } from "vitest";
import { parseGraphqlQuery, extractOperationName, isIntrospectionQuery, validateQueryDepth } from "./graphqlApi";

describe("parseGraphqlQuery", () => {
  it("parses valid query body", () => {
    const result = parseGraphqlQuery({ query: "{ scans { id } }", variables: { limit: 10 } });
    expect(result).not.toBeNull();
    expect(result!.query).toBe("{ scans { id } }");
    expect(result!.variables).toEqual({ limit: 10 });
  });

  it("rejects missing query", () => {
    expect(parseGraphqlQuery({ variables: {} })).toBeNull();
    expect(parseGraphqlQuery(null)).toBeNull();
    expect(parseGraphqlQuery("string")).toBeNull();
  });

  it("handles missing variables", () => {
    const result = parseGraphqlQuery({ query: "{ scan(id: 1) { id } }" });
    expect(result!.variables).toBeUndefined();
  });
});

describe("extractOperationName", () => {
  it("extracts query operation name", () => {
    expect(extractOperationName("query GetScans { scans { id } }")).toBe("GetScans");
  });

  it("extracts mutation operation name", () => {
    expect(extractOperationName("mutation RunScan($url: String!) { runScan(url: $url) }")).toBe("RunScan");
  });

  it("returns null for anonymous queries", () => {
    expect(extractOperationName("{ scans { id } }")).toBeNull();
  });
});

describe("isIntrospectionQuery", () => {
  it("detects __schema", () => {
    expect(isIntrospectionQuery("{ __schema { types { name } } }")).toBe(true);
  });

  it("detects __type", () => {
    expect(isIntrospectionQuery('{ __type(name: "Scan") { fields { name } } }')).toBe(true);
  });

  it("returns false for normal queries", () => {
    expect(isIntrospectionQuery("{ scans { id } }")).toBe(false);
  });
});

describe("validateQueryDepth", () => {
  it("accepts shallow queries", () => {
    expect(validateQueryDepth("{ scans { id findings { title } } }")).toBe(true);
  });

  it("rejects deeply nested queries", () => {
    const deep = "{ a { b { c { d { e { f { g { h { i } } } } } } } } }";
    expect(validateQueryDepth(deep, 7)).toBe(false);
  });

  it("accepts queries at exactly max depth", () => {
    const exact = "{ a { b { c { d { e { f { g } } } } } } }";
    expect(validateQueryDepth(exact, 7)).toBe(true);
  });
});
