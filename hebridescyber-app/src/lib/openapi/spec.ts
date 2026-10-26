// OpenAPI 3.1 description of the public /api/v1 surface. Hand-maintained rather
// than generated: the routes validate with ad-hoc code in places, so there is
// no single schema source to generate from yet. openapi.test.ts is the drift
// guard — it fails if a route file under src/pages/api/v1 has no path here,
// or if a documented method is not handled by that route.
//
// Scope: only what the code does today. Things the platform strategy plans
// (scopes, cursor pagination, error codes everywhere) are NOT described here
// until they exist. Error bodies are `{ error: string }`, with an optional
// machine-readable `code` on the few responses that carry one.

const SEVERITY = { type: "string", enum: ["critical", "high", "medium", "low", "info"] } as const;

const errorResponse = (description: string) => ({
  description,
  content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
});

const SCAN_ID = {
  name: "id",
  in: "path",
  required: true,
  description: "Scan id (UUID) returned by `POST /scans`.",
  schema: { type: "string", format: "uuid" },
} as const;

const COMMON_ERRORS = {
  "401": { $ref: "#/components/responses/Unauthorized" },
  "403": { $ref: "#/components/responses/InsufficientScope" },
  "429": { $ref: "#/components/responses/RateLimited" },
} as const;

const OWNED_SCAN_ERRORS = {
  ...COMMON_ERRORS,
  "403": errorResponse("The API key lacks the `scans:read` scope (`code: insufficient_scope`), or the scan belongs to another account."),
  "404": errorResponse("No such scan, or it has no results yet."),
} as const;

export const OPENAPI_VERSION = "1.0.0";

export function buildOpenApiSpec(serverUrl: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "Hebrides Cyber API",
      version: OPENAPI_VERSION,
      summary: "Queue security scans and read their results.",
      description:
        "Authenticate with `Authorization: Bearer <api-key>` (keys are created in the dashboard and look like `hc_live_…`). " +
        "Scans are asynchronous: `POST /scans` answers 202 immediately; poll `GET /scans/{id}` until `status` is `completed`, or register a webhook for `scan.completed`. " +
        "Only domains verified on your account can be scanned.\n\n" +
        "**Compatibility:** `/v1` changes are additive. Fields may be added to responses; existing fields are not removed or retyped.\n\n" +
        "Scan output is an automated indicator, not a certification or a guarantee that a site is secure.",
      contact: { name: "Hebrides Cyber", url: "https://www.hebridescyber.co.uk/contact" },
    },
    servers: [{ url: serverUrl }],
    security: [{ bearerAuth: [] }],
    tags: [
      { name: "Scans", description: "Queue and read scans." },
      { name: "Exports", description: "A scan's results in other formats." },
      { name: "Trends", description: "History over time." },
      { name: "CI", description: "Pull-request checks." },
    ],
    paths: {
      "/scans": {
        get: {
          operationId: "listScans",
          tags: ["Scans"],
          summary: "List your scans, newest first.",
          parameters: [
            { name: "limit", in: "query", description: "Page size. Default 20, maximum 100.", schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } },
            { name: "target_url", in: "query", description: "Only scans of exactly this target URL.", schema: { type: "string", format: "uri" } },
          ],
          responses: {
            "200": {
              description: "Scans, newest first. There is no cursor yet: use `limit` and `target_url` to narrow.",
              content: { "application/json": { schema: { $ref: "#/components/schemas/ScanList" } } },
            },
            ...COMMON_ERRORS,
          },
        },
        post: {
          operationId: "createScan",
          tags: ["Scans"],
          summary: "Queue a scan.",
          description:
            "Answers 202 as soon as the scan is queued; it usually completes within a minute. " +
            "If a scan of the same URL is already queued or running (started in the last 30 minutes) that scan is returned with `deduped: true` rather than creating another, so retrying is safe.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["target_url"],
                  additionalProperties: false,
                  properties: { target_url: { type: "string", format: "uri", example: "https://www.example.com" } },
                },
              },
            },
          },
          responses: {
            "202": {
              description: "Queued (or the existing in-flight scan).",
              content: { "application/json": { schema: { $ref: "#/components/schemas/ScanQueued" } } },
            },
            "400": errorResponse("Invalid body, or a target that is not allowed (private/reserved address)."),
            "402": {
              description: "The free scan has been used. `code` is `free_tier_exhausted`.",
              content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
            },
            ...COMMON_ERRORS,
            "403": errorResponse("The key lacks the `scans:write` scope (`code: insufficient_scope`), or the target's domain is not verified for this account (the body then includes `domain`)."),
          },
        },
      },
      "/scans/{id}": {
        get: {
          operationId: "getScan",
          tags: ["Scans"],
          summary: "A scan's result, with each finding marked new or unchanged against the previous scan of the same site.",
          description:
            "While the scan has no result yet this returns 200 with `findings: []` and a `status` such as `queued` or `running`.\n\n" +
            "`status` on a finding is `null` when there is nothing to compare against — check `compared_to_previous_scan` before relying on it, " +
            "and treat `false` as \"cannot tell what is new\", not \"nothing is new\".",
          parameters: [SCAN_ID],
          responses: {
            "200": { description: "The scan report.", content: { "application/json": { schema: { $ref: "#/components/schemas/ScanReport" } } } },
            ...OWNED_SCAN_ERRORS,
          },
        },
      },
      "/scans/{id}/export": {
        get: {
          operationId: "exportScanFindings",
          tags: ["Exports"],
          summary: "Findings as flat CSV or JSON, with the account's current triage decision per finding.",
          parameters: [
            SCAN_ID,
            { name: "format", in: "query", description: "Default `csv`.", schema: { type: "string", enum: ["csv", "json"], default: "csv" } },
          ],
          responses: {
            "200": {
              description: "A downloadable file.",
              content: {
                "text/csv": { schema: { type: "string" } },
                "application/json": { schema: { type: "object", properties: { scan_id: { type: "string" }, target_url: { type: "string" }, findings: { type: "array", items: { type: "object", additionalProperties: true } } } } },
              },
            },
            ...OWNED_SCAN_ERRORS,
          },
        },
      },
      "/scans/{id}/compliance": {
        get: {
          operationId: "getScanComplianceReport",
          tags: ["Exports"],
          summary: "Findings mapped to compliance framework controls (Cyber Essentials, ISO 27001, PCI DSS, OWASP Top 10, CIS v8, NIS2, DORA).",
          description: "An automated indicator for handing to an auditor. It is not a certification, and its wording is \"no issues found\", never \"pass\".",
          parameters: [
            SCAN_ID,
            { name: "format", in: "query", description: "Default `md`.", schema: { type: "string", enum: ["md", "csv", "json"], default: "md" } },
          ],
          responses: {
            "200": {
              description: "A downloadable file.",
              content: {
                "text/markdown": { schema: { type: "string" } },
                "text/csv": { schema: { type: "string" } },
                "application/json": { schema: { type: "object", additionalProperties: true } },
              },
            },
            "400": errorResponse("`format` is not one of md, csv, json."),
            ...OWNED_SCAN_ERRORS,
          },
        },
      },
      "/scans/{id}/remediation-pack": {
        get: {
          operationId: "getScanRemediationPack",
          tags: ["Exports"],
          summary: "A Markdown fix guide for the scan's findings, ordered by priority.",
          parameters: [SCAN_ID],
          responses: {
            "200": { description: "A downloadable Markdown file.", content: { "text/markdown": { schema: { type: "string" } } } },
            ...OWNED_SCAN_ERRORS,
          },
        },
      },
      "/scans/{id}/sbom": {
        get: {
          operationId: "getScanSbom",
          tags: ["Exports"],
          summary: "CycloneDX 1.5 software bill of materials, with vulnerability exploitability (VEX) statements.",
          description: "Only available for scans of a target with a connected repository and a lockfile or dependency manifest; otherwise 404.",
          parameters: [SCAN_ID],
          responses: {
            "200": { description: "A CycloneDX document.", content: { "application/vnd.cyclonedx+json": { schema: { type: "object", additionalProperties: true } } } },
            ...OWNED_SCAN_ERRORS,
          },
        },
      },
      "/targets/{host}/trend": {
        get: {
          operationId: "getTargetTrend",
          tags: ["Trends"],
          summary: "Score history for a host across its completed scans, oldest first.",
          parameters: [
            { name: "host", in: "path", required: true, description: "Hostname, matched case-insensitively (not a URL).", schema: { type: "string", example: "www.example.com" } },
            { name: "limit", in: "query", description: "Most recent N points. Default 20, maximum 100.", schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } },
          ],
          responses: {
            "200": { description: "Score points.", content: { "application/json": { schema: { $ref: "#/components/schemas/TargetTrend" } } } },
            "400": errorResponse("`host` is missing."),
            ...COMMON_ERRORS,
          },
        },
      },
      "/dependency-diff": {
        post: {
          operationId: "dependencyDiff",
          tags: ["CI"],
          summary: "The vulnerable packages a pull request introduces.",
          description:
            "Send each lockfile's content on the PR's base and head; the response lists only what head adds that OSV.dev knows to be vulnerable. Stateless: nothing is stored. Pro and Agency plans.\n\n" +
            "A lookup failure is a 502 with `code: lookup_failed` — \"we do not know\", never \"clean\".",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["files"],
                  properties: {
                    files: {
                      type: "array",
                      minItems: 1,
                      description: "Up to the documented per-request maximum; total content is capped (25 MB request limit).",
                      items: {
                        type: "object",
                        required: ["name"],
                        properties: {
                          name: { type: "string", minLength: 1, maxLength: 300, example: "package-lock.json" },
                          base: { type: ["string", "null"], description: "Lockfile content on the base branch. null/omitted if the file is new." },
                          head: { type: ["string", "null"], description: "Lockfile content on the head branch. null/omitted if the file was deleted." },
                          base_companion: { type: ["string", "null"], description: "Companion manifest on base (for example package.json), where the lockfile needs one." },
                          head_companion: { type: ["string", "null"], description: "Companion manifest on head." },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            ...COMMON_ERRORS,
            "200": { description: "Completed check.", content: { "application/json": { schema: { $ref: "#/components/schemas/DependencyDiff" } } } },
            "400": errorResponse("Invalid body."),
            "403": {
              description: "The key lacks the `dependency:check` scope (`code: insufficient_scope`), or the plan is not Pro/Agency (`code: plan_required`).",
              content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
            },
            "502": {
              description: "The vulnerability lookup failed. `code` is `lookup_failed`.",
              content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "API key (hc_live_…)",
          description:
            "An API key from the dashboard (`hc_live_…`). Each key carries scopes — `scans:read` (read scans, exports, trends), `scans:write` (queue scans), `dependency:check` (PR dependency checks) — chosen when the key is created; create the narrowest key your integration needs. Keys created before scopes existed have all three. A key may also have an IP allowlist; a blocked request gets the same 401 as an unknown key.",
        },
      },
      responses: {
        InsufficientScope: errorResponse("The API key does not have the scope this operation needs. The body carries `code: insufficient_scope` and `required_scope`."),
        Unauthorized: errorResponse("Missing or invalid `Authorization` header (or the caller's IP is not on the key's allowlist)."),
        RateLimited: {
          description: "Too many requests. Wait `Retry-After` seconds.",
          headers: { "Retry-After": { description: "Seconds to wait before retrying.", schema: { type: "integer" } } },
          content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
        },
      },
      schemas: {
        Error: {
          type: "object",
          required: ["error"],
          properties: {
            error: { type: "string", description: "Human-readable message." },
            code: { type: "string", description: "Machine-readable code, present on a few responses (`free_tier_exhausted`, `plan_required`, `lookup_failed`, `insufficient_scope`)." },
            retry_after_seconds: { type: "integer", description: "On 429." },
            domain: { type: "string", description: "On 403 for an unverified domain." },
            required_scope: { type: "string", enum: ["scans:read", "scans:write", "dependency:check"], description: "On 403 `insufficient_scope`." },
          },
        },
        Severity: SEVERITY,
        ScanStatus: {
          type: "string",
          description: "Lifecycle state. Treat unknown values as non-terminal.",
          examples: ["queued", "running", "completed", "failed"],
        },
        ScanSummary: {
          type: "object",
          required: ["scan_id", "target_url", "status", "created_at"],
          properties: {
            scan_id: { type: "string", format: "uuid" },
            target_url: { type: "string" },
            status: { $ref: "#/components/schemas/ScanStatus" },
            created_at: { type: "string", format: "date-time" },
            score: { type: ["integer", "null"], minimum: 0, maximum: 100 },
            summary: { type: ["string", "null"] },
          },
        },
        ScanList: {
          type: "object",
          required: ["scans", "count"],
          properties: { scans: { type: "array", items: { $ref: "#/components/schemas/ScanSummary" } }, count: { type: "integer" } },
        },
        ScanQueued: {
          type: "object",
          required: ["scan_id", "target_url", "status"],
          properties: {
            scan_id: { type: "string", format: "uuid" },
            target_url: { type: "string" },
            status: { $ref: "#/components/schemas/ScanStatus" },
            deduped: { type: "boolean", description: "True when an in-flight scan of the same URL was returned instead of a new one." },
            message: { type: "string" },
          },
        },
        Finding: {
          type: "object",
          required: ["severity", "title", "detail", "check_id", "remediation", "status"],
          properties: {
            check_id: { type: ["string", "null"], description: "Stable id (`module.check` or `module.check:key`). Null on scans that predate finding identity.", example: "headers.csp-weak" },
            severity: { $ref: "#/components/schemas/Severity" },
            title: { type: "string" },
            detail: { type: "string" },
            remediation: { type: ["string", "null"] },
            status: { type: ["string", "null"], enum: ["new", "unchanged", null], description: "Against the previous scan of the same site; null when it cannot be compared." },
            cve_ids: { type: "array", items: { type: "string" }, description: "Present only for finding types that get a CVE lookup. `[]` means checked, none known." },
            corroborated_by: {
              type: "array",
              description: "Other tools that reported the same issue.",
              items: { type: "object", required: ["tool", "check_id", "title"], properties: { tool: { type: "string" }, check_id: { type: "string" }, title: { type: "string" } } },
            },
            proof_of_exploit: {
              type: "object",
              description: "Present only when a follow-up check reproduced the issue.",
              properties: { confirmed: { type: "boolean", const: true }, evidence: { type: "string" }, validated_at: { type: ["string", "null"], format: "date-time" } },
            },
            fix_difficulty: { type: "string" },
            estimated_fix_minutes: { type: "integer" },
            threat_intel: {
              type: "object",
              description: "CISA KEV and FIRST EPSS for CVE-backed findings. Absent means not looked up — unknown, not \"not exploited\".",
              properties: {
                known_exploited: { type: "boolean" },
                kev_cve_ids: { type: "array", items: { type: "string" } },
                ransomware: { type: "boolean" },
                epss: { type: "number", minimum: 0, maximum: 1 },
                epss_percentile: { type: "number", minimum: 0, maximum: 1 },
              },
            },
            triage: {
              type: ["object", "null"],
              description: "The account's current accept-risk / false-positive / snooze decision, or null.",
              properties: {
                state: { type: "string" },
                reason: { type: "string" },
                expires_at: { type: ["string", "null"], format: "date-time" },
                triaged_at: { type: "string", format: "date-time" },
              },
            },
          },
        },
        ScanReport: {
          type: "object",
          required: ["scan_id", "target_url", "status", "created_at", "score", "findings", "critical_paths"],
          properties: {
            scan_id: { type: "string", format: "uuid" },
            target_url: { type: "string" },
            status: { $ref: "#/components/schemas/ScanStatus" },
            created_at: { type: "string", format: "date-time" },
            completed_at: { type: "string", format: "date-time" },
            score: { type: ["integer", "null"], minimum: 0, maximum: 100, description: "Null until the scan completes." },
            summary: { type: ["string", "null"] },
            counts: { type: "object", additionalProperties: { type: "integer" }, description: "Findings per severity." },
            compared_to_previous_scan: { type: "boolean" },
            new_finding_count: { type: ["integer", "null"] },
            fixed_finding_count: { type: ["integer", "null"] },
            findings: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
            fixed_findings: {
              type: "array",
              items: { type: "object", properties: { check_id: { type: ["string", "null"] }, severity: { $ref: "#/components/schemas/Severity" }, title: { type: "string" } } },
            },
            critical_paths: {
              type: "array",
              description: "Chains of findings that together form an attack path. Always present; `[]` when none.",
              items: {
                type: "object",
                properties: {
                  title: { type: "string" },
                  narrative: { type: "string" },
                  severity: { $ref: "#/components/schemas/Severity" },
                  findingCheckIds: { type: "array", items: { type: "string" } },
                  steps: { type: "array", items: { type: "object", additionalProperties: true } },
                },
              },
            },
          },
        },
        TargetTrend: {
          type: "object",
          required: ["host", "points", "count"],
          properties: {
            host: { type: "string" },
            count: { type: "integer" },
            points: { type: "array", items: { type: "object", required: ["date", "score"], properties: { date: { type: "string", format: "date-time" }, score: { type: "integer" } } } },
          },
        },
        DependencyDiff: {
          type: "object",
          required: ["status"],
          properties: {
            status: { type: "string", const: "completed" },
            complete: { type: "boolean", description: "False when some files could not be covered; do not treat an empty result as clean." },
            notes: { type: "array", items: { type: "string" } },
            files: { type: "array", items: { type: "object", additionalProperties: true } },
            packages_added: { type: "integer" },
            vulnerabilities: { type: "array", items: { type: "object", additionalProperties: true } },
            counts: { type: "object", additionalProperties: { type: "integer" } },
          },
        },
      },
    },
  } as const;
}

export type OpenApiSpec = ReturnType<typeof buildOpenApiSpec>;
