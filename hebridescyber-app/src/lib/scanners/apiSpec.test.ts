import { describe, it, expect } from "vitest";
import { parseOpenApiSpec } from "./apiSpec";

describe("parseOpenApiSpec", () => {
  it("returns empty array for null/undefined input", () => {
    expect(parseOpenApiSpec(null)).toEqual([]);
    expect(parseOpenApiSpec(undefined)).toEqual([]);
  });

  it("returns empty array for spec with no paths", () => {
    expect(parseOpenApiSpec({ openapi: "3.0.0" })).toEqual([]);
    expect(parseOpenApiSpec({ openapi: "3.0.0", paths: {} })).toEqual([]);
  });

  it("parses simple GET endpoint", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/users": {
          get: {
            operationId: "listUsers",
          },
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0]).toMatchObject({
      method: "GET",
      path: "/api/users",
      operationId: "listUsers",
      requiresAuth: false,
      parameters: [],
    });
  });

  it("detects auth requirement from operation-level security", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/admin": {
          get: {
            security: [{ bearerAuth: [] }],
          },
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints[0].requiresAuth).toBe(true);
  });

  it("inherits auth from global security", () => {
    const spec = {
      openapi: "3.0.0",
      security: [{ apiKey: [] }],
      paths: {
        "/api/data": {
          get: {},
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints[0].requiresAuth).toBe(true);
  });

  it("operation-level empty security overrides global", () => {
    const spec = {
      openapi: "3.0.0",
      security: [{ apiKey: [] }],
      paths: {
        "/api/public": {
          get: {
            security: [],
          },
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints[0].requiresAuth).toBe(false);
  });

  it("extracts parameters", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/items": {
          get: {
            parameters: [
              { name: "page", in: "query", required: true },
              { name: "limit", in: "query" },
            ],
          },
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints[0].parameters).toEqual([
      { name: "page", in: "query", required: true },
      { name: "limit", in: "query", required: false },
    ]);
  });

  it("parses multiple methods on same path", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/items": {
          get: {},
          post: {},
          delete: {},
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints).toHaveLength(3);
    expect(endpoints.map((e) => e.method).sort()).toEqual(["DELETE", "GET", "POST"]);
  });

  it("skips non-HTTP-method keys like summary/description/parameters", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/items": {
          summary: "Item operations",
          get: {},
        },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].method).toBe("GET");
  });

  it("parses multiple paths", () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/users": { get: {} },
        "/api/posts": { get: {}, post: {} },
        "/api/health": { get: {} },
      },
    };
    const endpoints = parseOpenApiSpec(spec);
    expect(endpoints).toHaveLength(4);
  });
});
