// E-03 (docs/ENHANCEMENTS.md): shared beforeSend scrubbing, used by all
// three Sentry entry points (instrumentation-client.ts, sentry.server.config.ts,
// sentry.edge.config.ts) so the redaction list lives in exactly one place —
// not three copies that could drift apart on which fields are considered
// sensitive. Plain JS only (no Node builtins) since sentry.edge.config.ts
// runs in the Edge runtime, which can't use them.
//
// Sentry's SDK already does some default scrubbing (common secret-looking
// key names in request data), but this app has its own specific sensitive
// fields worth naming explicitly rather than trusting a generic heuristic:
// target-auth credentials (cookie_value/basic_username/basic_password —
// sql/migrations/014_target_auth_credentials.sql) and anything that looks
// like an API key/service-role/session token. Scan *findings* themselves
// are not scrubbed — they're the customer's own security data about their
// own site, not a credential, and stripping them would defeat the point of
// capturing a scan-processing error in the first place.
const SENSITIVE_KEY_RE = /(password|cookie_value|basic_username|secret|token|api_key|apikey|service_role|authorization)/i;

const REDACTED = "[Redacted]";

function scrubValue(value: unknown, depth: number): unknown {
  if (depth > 6) return value; // guard against pathological/circular-ish depth, not true cycles (JSON-shaped event data)
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = SENSITIVE_KEY_RE.test(key) ? REDACTED : scrubValue(val, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Sentry's beforeSend hook, shared across all three runtime entry points.
 * Scrubs request data/extra/contexts recursively; leaves the exception
 * message/stack trace and breadcrumb text alone (scrubbing those would make
 * errors much harder to actually debug, and they're far less likely to
 * carry a raw credential than structured request/context data is).
 */
export function scrubSentryEvent<T extends { request?: unknown; extra?: unknown; contexts?: unknown }>(event: T): T {
  return {
    ...event,
    request: event.request ? scrubValue(event.request, 0) : event.request,
    extra: event.extra ? scrubValue(event.extra, 0) : event.extra,
    contexts: event.contexts ? scrubValue(event.contexts, 0) : event.contexts,
  };
}
