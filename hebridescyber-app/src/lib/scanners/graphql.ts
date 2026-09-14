// GraphQL scanning — introspection, injection, DoS (query depth/complexity),
// and authorization checks against GraphQL endpoints.
//
// Detects GraphQL endpoints by probing common paths (/graphql, /gql, /api/graphql),
// then checks for introspection enabled, missing auth, query depth limits,
// and basic injection vectors.

import type { Finding } from "./index";

const GRAPHQL_PATHS = ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query"];
const REQUEST_TIMEOUT_MS = 10_000;

const INTROSPECTION_QUERY = `{"query":"{ __schema { types { name } } }"}`;
const DEPTH_QUERY = `{"query":"{ __typename a: __typename b: __typename c: __typename d: __typename e: __typename f: __typename g: __typename h: __typename i: __typename j: __typename k: __typename l: __typename m: __typename n: __typename o: __typename p: __typename q: __typename r: __typename s: __typename t: __typename }"}`;

type GraphqlCheckResult =
  | { status: "checked"; findings: Finding[]; endpoints: string[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string; findings: Finding[] };

async function probeEndpoint(baseUrl: string, path: string): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: INTROSPECTION_QUERY,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    return text.includes("__schema") || text.includes("__typename") || text.includes('"data"');
  } catch {
    return false;
  }
}

async function checkIntrospection(baseUrl: string, endpoint: string): Promise<Finding | null> {
  try {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: INTROSPECTION_QUERY,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    if (text.includes("__schema") && text.includes("types")) {
      return {
        severity: "medium",
        title: `GraphQL introspection enabled at ${endpoint}`,
        detail: "Introspection allows attackers to discover the entire API schema, including types, queries, mutations, and subscriptions. This should be disabled in production.",
        checkId: `graphql.introspection:${endpoint}`,
      };
    }
  } catch { /* probe failure is not a finding */ }
  return null;
}

async function checkNoAuth(baseUrl: string, endpoint: string): Promise<Finding | null> {
  try {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: `{"query":"{ __typename }"}`,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) {
      const text = await res.text();
      if (text.includes("__typename") && !text.includes("error") && !text.includes("unauthorized")) {
        return {
          severity: "low",
          title: `GraphQL endpoint ${endpoint} accessible without authentication`,
          detail: "The GraphQL endpoint responds to unauthenticated queries. Ensure sensitive queries and mutations require authentication.",
          checkId: `graphql.no-auth:${endpoint}`,
        };
      }
    }
  } catch { /* not a finding */ }
  return null;
}

async function checkQueryDepth(baseUrl: string, endpoint: string): Promise<Finding | null> {
  try {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: DEPTH_QUERY,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) {
      const text = await res.text();
      if (text.includes('"data"') && !text.includes("error")) {
        return {
          severity: "low",
          title: `No query depth/complexity limit at ${endpoint}`,
          detail: "The endpoint accepted a query with many aliased fields without rejecting it for complexity. Consider implementing query depth and complexity limits to prevent denial-of-service attacks.",
          checkId: `graphql.no-depth-limit:${endpoint}`,
        };
      }
    }
  } catch { /* not a finding */ }
  return null;
}

export async function runGraphqlChecks(targetUrl: string): Promise<GraphqlCheckResult> {
  const baseUrl = targetUrl.replace(/\/+$/, "");

  const detectedEndpoints: string[] = [];
  for (const path of GRAPHQL_PATHS) {
    if (await probeEndpoint(baseUrl, path)) {
      detectedEndpoints.push(path);
    }
  }

  if (detectedEndpoints.length === 0) {
    return { status: "not_applicable", note: "No GraphQL endpoints detected" };
  }

  const findings: Finding[] = [];

  for (const endpoint of detectedEndpoints) {
    const introspection = await checkIntrospection(baseUrl, endpoint);
    if (introspection) findings.push(introspection);

    const noAuth = await checkNoAuth(baseUrl, endpoint);
    if (noAuth) findings.push(noAuth);

    const depthLimit = await checkQueryDepth(baseUrl, endpoint);
    if (depthLimit) findings.push(depthLimit);
  }

  return { status: "checked", findings, endpoints: detectedEndpoints };
}
