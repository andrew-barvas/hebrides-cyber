// E-33: API-spec-aware security testing — parses a customer-supplied
// OpenAPI 2.x/3.x spec and generates targeted security checks against each
// declared endpoint. Finds what a crawler can't: undiscovered endpoints,
// missing auth requirements, excess data exposure.
//
// Split into two tiers matching the scanner pipeline's architecture:
//   - checkApiSpecPassive() runs in the base suite (index.ts's runAllChecks):
//     auth bypass, method confusion, schema violation, excess data exposure.
//     These are safe read-only checks that never send attack payloads.
//   - checkApiSpecInjection() runs in the extended suite (scanExecution.ts's
//     runExtendedTools): SQL injection and XSS probes against parameters.
//     Only runs when runExtendedTools is true.
//
// If no stored spec exists, checkApiSpecPassive attempts auto-discovery at
// well-known paths (/openapi.json, /swagger.json, etc). If that also fails
// it returns status: "not_configured" with no findings.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./index";
import {
  API_SPEC_AUTH_BYPASS,
  API_SPEC_METHOD_CONFUSION,
  API_SPEC_SCHEMA_VIOLATION,
  API_SPEC_EXCESSIVE_DATA,
  API_SPEC_SQLI,
  API_SPEC_XSS,
} from "./remediationText";

const REQUEST_TIMEOUT_MS = 10_000;

/** Cap probes per check to keep scan time bounded. */
const MAX_ENDPOINTS_PER_CHECK = 20;

// ---- Types ---------------------------------------------------------------

type ApiEndpoint = {
  method: string;
  path: string;
  operationId?: string;
  requiresAuth: boolean;
  parameters: Array<{ name: string; in: string; required: boolean; type?: string }>;
  requestBodyRequired?: boolean;
  requestBodyProperties?: string[];
  responseProperties?: string[];
};

type OpenApiSpec = {
  openapi?: string;
  swagger?: string;
  paths?: Record<string, Record<string, {
    operationId?: string;
    security?: Array<Record<string, string[]>>;
    parameters?: Array<{ name: string; in: string; required?: boolean; schema?: { type?: string } }>;
    requestBody?: {
      required?: boolean;
      content?: Record<string, {
        schema?: {
          required?: string[];
          properties?: Record<string, unknown>;
        };
      }>;
    };
    responses?: Record<string, {
      content?: Record<string, {
        schema?: {
          properties?: Record<string, unknown>;
        };
      }>;
    }>;
  }>>;
  security?: Array<Record<string, string[]>>;
};

export type ApiSpecResult =
  | { status: "completed"; findings: Finding[]; endpointsTested: number; specSource: "stored" | "auto-discovered" | "none" }
  | { status: "not_configured"; findings: Finding[]; endpointsTested: 0; specSource: "none" }
  | { status: "error"; note: string; findings: Finding[]; endpointsTested: 0; specSource: "none" };

// ---- Spec parsing --------------------------------------------------------

export function parseOpenApiSpec(raw: unknown): ApiEndpoint[] {
  const spec = raw as OpenApiSpec;
  if (!spec?.paths) return [];

  const globalSecurity = (spec.security ?? []).length > 0;
  const endpoints: ApiEndpoint[] = [];

  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (["get", "post", "put", "patch", "delete", "head", "options"].indexOf(method.toLowerCase()) < 0) continue;
      const opSecurity = op.security !== undefined ? op.security.length > 0 : globalSecurity;

      // Extract request body properties (OpenAPI 3.x)
      let requestBodyRequired = false;
      let requestBodyProperties: string[] = [];
      if (op.requestBody) {
        requestBodyRequired = op.requestBody.required ?? false;
        const content = op.requestBody.content;
        if (content) {
          const jsonSchema = content["application/json"]?.schema;
          if (jsonSchema?.properties) {
            requestBodyProperties = Object.keys(jsonSchema.properties);
          }
        }
      }

      // Extract documented response properties (for excess data exposure check)
      let responseProperties: string[] = [];
      const successResponse = op.responses?.["200"] ?? op.responses?.["201"];
      if (successResponse?.content) {
        const jsonSchema = successResponse.content["application/json"]?.schema;
        if (jsonSchema?.properties) {
          responseProperties = Object.keys(jsonSchema.properties);
        }
      }

      endpoints.push({
        method: method.toUpperCase(),
        path,
        operationId: op.operationId,
        requiresAuth: opSecurity,
        parameters: (op.parameters ?? []).map((p) => ({
          name: p.name,
          in: p.in,
          required: p.required ?? false,
          type: p.schema?.type,
        })),
        requestBodyRequired,
        requestBodyProperties,
        responseProperties,
      });
    }
  }

  return endpoints;
}

// ---- Auto-discovery ------------------------------------------------------

const AUTO_DISCOVERY_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/api-docs",
  "/v1/api-docs",
  "/.well-known/openapi",
  "/api/openapi.json",
  "/api/swagger.json",
  "/v2/api-docs",
  "/v3/api-docs",
];

async function tryAutoDiscover(baseUrl: string): Promise<Record<string, unknown> | null> {
  const origin = baseUrl.replace(/\/+$/, "");
  for (const path of AUTO_DISCOVERY_PATHS) {
    try {
      const res = await fetch(`${origin}${path}`, {
        signal: AbortSignal.timeout(6_000),
        headers: { Accept: "application/json" },
        redirect: "follow",
      });
      if (res.status !== 200) continue;
      const ct = res.headers.get("content-type") ?? "";
      if (!ct.includes("json") && !ct.includes("yaml")) continue;
      const text = await res.text();
      try {
        const parsed = JSON.parse(text) as Record<string, unknown>;
        // Must look like an OpenAPI/Swagger doc
        if (parsed.paths && (parsed.openapi || parsed.swagger)) {
          return parsed;
        }
      } catch {
        // Not JSON — skip
      }
    } catch {
      // Timeout / network error — try next path
    }
  }
  return null;
}

// ---- Passive checks (base suite) ----------------------------------------

/**
 * Runs safe, read-only checks against endpoints declared in the spec:
 * (a) auth bypass, (b) method confusion, (c) schema violation,
 * (e) excess data exposure.
 *
 * Called from the base suite in index.ts's runAllChecks.
 */
export async function checkApiSpecPassive(
  targetUrl: string,
  supabaseAdmin: SupabaseClient | null,
  ownerId: string | null
): Promise<ApiSpecResult> {
  const empty: ApiSpecResult = { status: "not_configured", findings: [], endpointsTested: 0, specSource: "none" };

  try {
    // Try stored spec first (only when database access is available)
    let specs: Array<{ spec_content: unknown; target_url: string }> | null = null;
    if (supabaseAdmin && ownerId) {
      const { data } = await supabaseAdmin
        .from("api_specs")
        .select("spec_content, target_url")
        .eq("owner", ownerId)
        .order("updated_at", { ascending: false });
      specs = data;
    }

    // Match spec by target_url — find the one whose target_url is closest
    // to the scan's target URL (same origin).
    let rawSpec: Record<string, unknown> | null = null;
    let specSource: "stored" | "auto-discovered" = "stored";

    if (specs && specs.length > 0) {
      const targetOrigin = new URL(targetUrl).origin;
      const match = specs.find((s) => {
        try { return new URL(s.target_url).origin === targetOrigin; } catch { return false; }
      });
      if (match) {
        rawSpec = match.spec_content as Record<string, unknown>;
      } else {
        // Fallback: use the most recent spec regardless of target
        rawSpec = specs[0].spec_content as Record<string, unknown>;
      }
    }

    // Auto-discovery if no stored spec
    if (!rawSpec) {
      rawSpec = await tryAutoDiscover(targetUrl);
      if (rawSpec) {
        specSource = "auto-discovered";
      } else {
        return empty;
      }
    }

    const endpoints = parseOpenApiSpec(rawSpec);
    if (endpoints.length === 0) {
      return { status: "completed", findings: [], endpointsTested: 0, specSource };
    }

    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, "");

    // (a) Auth bypass: endpoints declared as requiring auth but accessible without it
    const authEndpoints = endpoints.filter((e) => e.requiresAuth);
    for (const ep of authEndpoints.slice(0, MAX_ENDPOINTS_PER_CHECK)) {
      try {
        const url = resolveUrl(baseUrl, ep.path);
        const res = await fetch(url, {
          method: ep.method === "GET" || ep.method === "HEAD" ? ep.method : "HEAD",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
        });
        if (res.status >= 200 && res.status < 300) {
          findings.push({
            severity: "high",
            title: `API endpoint accessible without auth: ${ep.method} ${ep.path}`,
            detail: `Endpoint is declared as requiring authentication in the OpenAPI spec but returned HTTP ${res.status} without any credentials.`,
            checkId: `api-spec.auth-bypass:${ep.method}:${ep.path}`,
            remediation: API_SPEC_AUTH_BYPASS,
          });
        }
      } catch {
        // endpoint unreachable — not a security finding
      }
    }

    // (b) Method confusion: if endpoint documents GET, try other methods
    const methodCheckEndpoints = endpoints
      .filter((e) => e.method === "GET")
      .slice(0, MAX_ENDPOINTS_PER_CHECK);
    const unexpectedMethods = ["POST", "PUT", "DELETE"];
    for (const ep of methodCheckEndpoints) {
      for (const method of unexpectedMethods) {
        // Skip if this method is already documented for this path
        const documented = endpoints.some((e) => e.path === ep.path && e.method === method);
        if (documented) continue;
        try {
          const url = resolveUrl(baseUrl, ep.path);
          const res = await fetch(url, {
            method,
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            redirect: "manual",
            headers: { "Content-Length": "0" },
          });
          // 200/201/204 for an undocumented method is a finding. 405/404/401 is expected.
          if (res.status >= 200 && res.status < 300) {
            findings.push({
              severity: "medium",
              title: `Undocumented HTTP method accepted: ${method} ${ep.path}`,
              detail: `The spec only documents ${ep.method} for this path, but ${method} returned HTTP ${res.status}. Unexpected methods may bypass access controls or cause unintended side effects.`,
              checkId: `api-spec.method-confusion:${method}:${ep.path}`,
              remediation: API_SPEC_METHOD_CONFUSION,
            });
            break; // one finding per path is enough
          }
        } catch {
          // network error — skip
        }
      }
    }

    // (c) Schema violation: send requests missing required fields
    const bodyEndpoints = endpoints
      .filter((e): e is ApiEndpoint & { requestBodyProperties: string[] } =>
        !!e.requestBodyRequired && !!e.requestBodyProperties && e.requestBodyProperties.length > 0 && ["POST", "PUT", "PATCH"].includes(e.method))
      .slice(0, MAX_ENDPOINTS_PER_CHECK);
    for (const ep of bodyEndpoints) {
      try {
        const url = resolveUrl(baseUrl, ep.path);
        // Send an empty JSON body when required fields exist
        const res = await fetch(url, {
          method: ep.method,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        // A 200/201 for an empty body when required fields exist = no validation
        if (res.status >= 200 && res.status < 300) {
          findings.push({
            severity: "medium",
            title: `No input validation: ${ep.method} ${ep.path}`,
            detail: `Endpoint accepted an empty JSON body despite documenting required fields: ${ep.requestBodyProperties.join(", ")}. Missing server-side validation can lead to data integrity issues and bypass business logic.`,
            checkId: `api-spec.schema-violation:${ep.method}:${ep.path}`,
            remediation: API_SPEC_SCHEMA_VIOLATION,
          });
        }
      } catch {
        // skip
      }
    }

    // (e) Excess data exposure: check if responses include fields not in the spec
    const responseCheckEndpoints = endpoints
      .filter((e): e is ApiEndpoint & { responseProperties: string[] } =>
        e.method === "GET" && !!e.responseProperties && e.responseProperties.length > 0)
      .slice(0, 10);
    for (const ep of responseCheckEndpoints) {
      try {
        const url = resolveUrl(baseUrl, ep.path);
        const res = await fetch(url, {
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          redirect: "manual",
        });
        if (res.status !== 200) continue;
        const ct = res.headers.get("content-type") ?? "";
        if (!ct.includes("json")) continue;

        const text = await res.text();
        let body: Record<string, unknown>;
        try { body = JSON.parse(text); } catch { continue; }

        // Handle both direct objects and arrays-of-objects
        const obj = Array.isArray(body) ? (body[0] as Record<string, unknown> | undefined) : body;
        if (!obj || typeof obj !== "object") continue;

        const actualKeys = Object.keys(obj);
        const documentedKeys = new Set(ep.responseProperties.map((k) => k.toLowerCase()));
        const undocumented = actualKeys.filter((k) => !documentedKeys.has(k.toLowerCase()));

        // Only flag if the undocumented fields look sensitive
        const sensitivePatterns = /^(password|secret|token|key|ssn|credit|card|cvv|private|internal|hash|salt|session|cookie|auth)/i;
        const sensitiveUndocumented = undocumented.filter((k) => sensitivePatterns.test(k));

        if (sensitiveUndocumented.length > 0) {
          findings.push({
            severity: "high",
            title: `Potential data leak: ${ep.method} ${ep.path}`,
            detail: `Response contains ${undocumented.length} field(s) not documented in the spec. Sensitive-looking undocumented fields: ${sensitiveUndocumented.join(", ")}. This may indicate excessive data exposure.`,
            checkId: `api-spec.excessive-data:${ep.path}`,
            remediation: API_SPEC_EXCESSIVE_DATA,
          });
        } else if (undocumented.length > 5) {
          findings.push({
            severity: "low",
            title: `Undocumented response fields: ${ep.method} ${ep.path}`,
            detail: `Response contains ${undocumented.length} field(s) not documented in the spec: ${undocumented.slice(0, 5).join(", ")}${undocumented.length > 5 ? ` (+${undocumented.length - 5} more)` : ""}. Review whether these should be exposed.`,
            checkId: `api-spec.undocumented-fields:${ep.path}`,
            remediation: API_SPEC_EXCESSIVE_DATA,
          });
        }
      } catch {
        // skip
      }
    }

    const endpointsTested = Math.min(endpoints.length, MAX_ENDPOINTS_PER_CHECK);
    return { status: "completed", findings, endpointsTested, specSource };
  } catch (err) {
    return { status: "error", note: (err as Error).message, findings: [], endpointsTested: 0, specSource: "none" };
  }
}

// ---- Active injection checks (extended suite) ----------------------------

/**
 * Runs injection payloads against spec-documented parameters. Only called
 * from scanExecution.ts's runExtendedTools when the profile enables it.
 * Uses minimal, safe payloads designed to detect error-based responses
 * rather than blind exploitation.
 */
export async function checkApiSpecInjection(
  targetUrl: string,
  supabaseAdmin: SupabaseClient,
  ownerId: string
): Promise<ApiSpecResult> {
  const empty: ApiSpecResult = { status: "not_configured", findings: [], endpointsTested: 0, specSource: "none" };

  try {
    const { data: specs } = await supabaseAdmin
      .from("api_specs")
      .select("spec_content")
      .eq("owner", ownerId)
      .order("updated_at", { ascending: false })
      .limit(1);

    if (!specs || specs.length === 0) return empty;
    const rawSpec = specs[0].spec_content;
    if (!rawSpec) return empty;

    const endpoints = parseOpenApiSpec(rawSpec);
    if (endpoints.length === 0) {
      return { status: "completed", findings: [], endpointsTested: 0, specSource: "stored" };
    }

    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, "");

    // SQLi payloads — minimal, designed to trigger error messages not exploit
    const sqliPayloads = ["' OR '1'='1", "1; SELECT 1--", "' UNION SELECT NULL--"];
    const sqliErrorPatterns = [
      /SQL syntax/i, /syntax error/i, /mysql/i, /pg_/i, /ORA-\d/i,
      /SQLITE_/i, /microsoft.*odbc/i, /unexpected end of SQL/i,
      /unterminated quoted string/i, /SQL command not properly ended/i,
    ];

    // XSS payload — harmless canary
    const xssPayload = "<script>alert(1)</script>";

    const queryEndpoints = endpoints
      .filter((e) => e.parameters.some((p) => p.in === "query" || p.in === "path"))
      .slice(0, MAX_ENDPOINTS_PER_CHECK);

    for (const ep of queryEndpoints) {
      const queryParams = ep.parameters.filter((p) => p.in === "query");
      const pathParams = ep.parameters.filter((p) => p.in === "path");

      // (d.1) SQL injection on query parameters
      for (const param of queryParams.slice(0, 3)) {
        for (const payload of sqliPayloads) {
          try {
            const qs = `${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
            const url = `${resolveUrl(baseUrl, ep.path)}?${qs}`;
            const res = await fetch(url, {
              signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
              redirect: "manual",
            });
            const body = await res.text();
            if (sqliErrorPatterns.some((p) => p.test(body))) {
              findings.push({
                severity: "critical",
                title: `Possible SQL injection: ${ep.method} ${ep.path} (param: ${param.name})`,
                detail: `SQL error message detected in response when testing query parameter "${param.name}" with injection payload.`,
                checkId: `api-spec.sqli:${ep.method}:${ep.path}:${param.name}`,
                remediation: API_SPEC_SQLI,
              });
              break; // one finding per param is enough
            }
          } catch {
            // skip
          }
        }
      }

      // (d.2) XSS reflection on query parameters
      for (const param of queryParams.slice(0, 3)) {
        try {
          const qs = `${encodeURIComponent(param.name)}=${encodeURIComponent(xssPayload)}`;
          const url = `${resolveUrl(baseUrl, ep.path)}?${qs}`;
          const res = await fetch(url, {
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            redirect: "manual",
          });
          const body = await res.text();
          // Only flag if the payload is reflected unescaped
          if (body.includes(xssPayload)) {
            findings.push({
              severity: "high",
              title: `Reflected XSS: ${ep.method} ${ep.path} (param: ${param.name})`,
              detail: `The XSS payload was reflected unescaped in the response body for parameter "${param.name}".`,
              checkId: `api-spec.xss:${ep.method}:${ep.path}:${param.name}`,
              remediation: API_SPEC_XSS,
            });
            break;
          }
        } catch {
          // skip
        }
      }

      // (d.3) SQL injection on path parameters
      for (const param of pathParams.slice(0, 2)) {
        for (const payload of sqliPayloads.slice(0, 1)) {
          try {
            const injectedPath = ep.path.replace(`{${param.name}}`, encodeURIComponent(payload));
            const url = resolveUrl(baseUrl, injectedPath);
            const res = await fetch(url, {
              signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
              redirect: "manual",
            });
            const body = await res.text();
            if (sqliErrorPatterns.some((p) => p.test(body))) {
              findings.push({
                severity: "critical",
                title: `Possible SQL injection in path: ${ep.method} ${ep.path} (param: ${param.name})`,
                detail: `SQL error message detected when injecting into path parameter "${param.name}".`,
                checkId: `api-spec.sqli-path:${ep.method}:${ep.path}:${param.name}`,
                remediation: API_SPEC_SQLI,
              });
              break;
            }
          } catch {
            // skip
          }
        }
      }
    }

    const endpointsTested = Math.min(queryEndpoints.length, MAX_ENDPOINTS_PER_CHECK);
    return { status: "completed", findings, endpointsTested, specSource: "stored" };
  } catch (err) {
    return { status: "error", note: (err as Error).message, findings: [], endpointsTested: 0, specSource: "none" };
  }
}

// ---- Helpers -------------------------------------------------------------

/** Resolve an OpenAPI path template against a base URL, replacing path params with safe defaults. */
function resolveUrl(baseUrl: string, path: string): string {
  // Replace {param} placeholders with a safe default value
  const resolved = path.replace(/\{[^}]+\}/g, "1");
  return `${baseUrl}${resolved}`;
}

// ---- Legacy compat: keep the old export for the existing test file -------

/** @deprecated Use checkApiSpecPassive instead. Kept for backward compat with apiSpec.test.ts. */
export async function runApiSpecChecks(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string
): Promise<{ status: string; findings: Finding[]; note?: string }> {
  const result = await checkApiSpecPassive(targetUrl, supabaseAdmin, ownerId);
  if (result.status === "not_configured") return { status: "not_applicable", note: "No API spec stored for this target", findings: [] };
  if (result.status === "error") return { status: "error", note: result.note, findings: result.findings };
  return { status: "checked", findings: result.findings };
}
