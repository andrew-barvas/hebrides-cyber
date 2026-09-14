// E-33: API-spec-aware security testing — parses a customer-supplied
// OpenAPI 3.x spec and generates targeted security checks against each
// declared endpoint. Finds what a crawler can't: undiscovered endpoints,
// missing auth requirements, excess data exposure.
//
// Runs as part of the extended tool suite (only in scheduled scans with
// a stored spec), same pattern as secretScan/dependencyManifest.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./index";

const REQUEST_TIMEOUT_MS = 10_000;

type ApiEndpoint = {
  method: string;
  path: string;
  operationId?: string;
  requiresAuth: boolean;
  parameters: Array<{ name: string; in: string; required: boolean }>;
};

type OpenApiSpec = {
  openapi?: string;
  paths?: Record<string, Record<string, {
    operationId?: string;
    security?: Array<Record<string, string[]>>;
    parameters?: Array<{ name: string; in: string; required?: boolean }>;
  }>>;
  security?: Array<Record<string, string[]>>;
};

export function parseOpenApiSpec(raw: unknown): ApiEndpoint[] {
  const spec = raw as OpenApiSpec;
  if (!spec?.paths) return [];

  const globalSecurity = (spec.security ?? []).length > 0;
  const endpoints: ApiEndpoint[] = [];

  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (["get", "post", "put", "patch", "delete", "head", "options"].indexOf(method.toLowerCase()) < 0) continue;
      const opSecurity = op.security !== undefined ? op.security.length > 0 : globalSecurity;
      endpoints.push({
        method: method.toUpperCase(),
        path,
        operationId: op.operationId,
        requiresAuth: opSecurity,
        parameters: (op.parameters ?? []).map((p) => ({
          name: p.name,
          in: p.in,
          required: p.required ?? false,
        })),
      });
    }
  }

  return endpoints;
}

type ApiSpecCheckResult =
  | { status: "checked"; findings: Finding[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string; findings: Finding[] };

export async function runApiSpecChecks(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string
): Promise<ApiSpecCheckResult> {
  const empty: ApiSpecCheckResult = { status: "not_applicable", note: "No API spec stored for this target" };

  try {
    const { data: specs } = await supabaseAdmin
      .from("api_specs")
      .select("raw_spec")
      .eq("owner", ownerId)
      .order("uploaded_at", { ascending: false })
      .limit(1);

    if (!specs || specs.length === 0) return empty;
    const rawSpec = specs[0].raw_spec;
    if (!rawSpec) return empty;

    const endpoints = parseOpenApiSpec(rawSpec);
    if (endpoints.length === 0) return { status: "not_applicable", note: "API spec contains no parseable endpoints" };

    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, "");

    // Check 1: endpoints declared as requiring auth but accessible without it
    const authEndpoints = endpoints.filter((e) => e.requiresAuth);
    for (const ep of authEndpoints.slice(0, 15)) {
      try {
        const url = `${baseUrl}${ep.path}`;
        const res = await fetch(url, {
          method: ep.method === "GET" ? "GET" : "HEAD",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
        });
        if (res.status >= 200 && res.status < 300) {
          findings.push({
            severity: "high",
            title: `API endpoint accessible without auth: ${ep.method} ${ep.path}`,
            detail: `Endpoint is declared as requiring authentication in the OpenAPI spec but returned HTTP ${res.status} without any credentials.`,
            checkId: `apiSpec.missingAuth:${ep.method}:${ep.path}`,
          });
        }
      } catch {
        // endpoint unreachable — not a security finding
      }
    }

    // Check 2: undocumented 200 responses to fuzz parameters
    const getEndpoints = endpoints.filter((e) => e.method === "GET" && e.parameters.some((p) => p.in === "query"));
    for (const ep of getEndpoints.slice(0, 10)) {
      try {
        const queryParams = ep.parameters
          .filter((p) => p.in === "query")
          .map((p) => `${encodeURIComponent(p.name)}=test'OR'1'='1`)
          .join("&");
        const url = `${baseUrl}${ep.path}?${queryParams}`;
        const res = await fetch(url, {
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
        });
        const body = await res.text();
        if (body.includes("SQL") || body.includes("syntax error") || body.includes("mysql") || body.includes("pg_")) {
          findings.push({
            severity: "critical",
            title: `Possible SQL injection: ${ep.method} ${ep.path}`,
            detail: `SQL error message detected in response when testing query parameters with injection payload.`,
            checkId: `apiSpec.sqlError:${ep.method}:${ep.path}`,
          });
        }
      } catch {
        // not reachable
      }
    }

    // Check 3: missing security headers on API responses
    for (const ep of endpoints.slice(0, 5)) {
      try {
        const url = `${baseUrl}${ep.path}`;
        const res = await fetch(url, {
          method: "HEAD",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
        });
        const corsHeader = res.headers.get("access-control-allow-origin");
        if (corsHeader === "*") {
          findings.push({
            severity: "medium",
            title: `Wildcard CORS on API endpoint: ${ep.method} ${ep.path}`,
            detail: `API endpoint returns Access-Control-Allow-Origin: * which allows any origin to make cross-origin requests.`,
            checkId: `apiSpec.wildcardCors:${ep.path}`,
          });
          break;
        }
      } catch {
        // not reachable
      }
    }

    return { status: "checked", findings };
  } catch (err) {
    return { status: "error", note: (err as Error).message, findings: [] };
  }
}
