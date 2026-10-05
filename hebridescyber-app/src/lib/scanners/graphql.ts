// GraphQL exposure check.
//
// Finds GraphQL endpoints and reports what a stranger can learn from them:
// whether schema introspection is open, whether the server leaks schema names
// through "Did you mean" suggestions when introspection is off, and whether a
// GraphiQL/Playground-style IDE is served. Read-only: every request is a query
// for type names or a deliberately mistyped field, never a mutation, and no
// data is read (introspection is asked for type NAMES and a count only).
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
// - An endpoint exists only if the response parses as JSON and has GraphQL's
//   own shape (`data.__typename`, or an `errors` entry carrying a GraphQL
//   validator message). A catch-all that answers every POST with a page or
//   `{"data": ...}`-looking JSON of its own is therefore not a GraphQL endpoint.
// - Introspection counts as open only when `data.__schema.types` is a real
//   list. IDEs are matched on their own page text, not on a 200.
// - If every probe failed at the network level the result is "error", not
//   "no GraphQL here".
// Removed from the first version of this module, as unevidenced: "accessible
// without authentication" (`__typename` is answered for anyone, by design) and
// "no query depth limit" (accepting 20 aliases proves nothing about limits).
import type { Finding } from "./index";
import * as FIX from "./remediationText";

export const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/v1/graphql", "/query"] as const;
export const IDE_PATHS = ["/graphiql", "/playground", "/altair", "/voyager"] as const;
const REQUEST_TIMEOUT_MS = 8_000;
const MAX_BODY_CHARS = 200_000;

const TYPENAME_QUERY = `{"query":"{ __typename }"}`;
const SCHEMA_QUERY = `{"query":"{ __schema { types { name } } }"}`;
const TYPO_QUERY = `{"query":"{ __typenam }"}`;

const GRAPHQL_ERROR_RE = /Cannot query field|Unknown (?:field|type|argument)|Syntax Error|Validation error|must provide (?:a )?query|GraphQL/i;
const IDE_RE = /GraphiQL|GraphQL Playground|Apollo Sandbox|Altair GraphQL|GraphQL Voyager/i;

export type GraphqlEndpoint = {
  path: string;
  introspection: { open: boolean; typeCount: number };
  /** Introspection is off but a mistyped field still gets a "Did you mean" suggestion. */
  suggestionsLeak: boolean;
};

export type GraphqlResult =
  | { status: "checked"; endpoints: GraphqlEndpoint[]; ides: string[] }
  | { status: "not_applicable" }
  | { status: "error"; note: string };

type Json = Record<string, unknown>;

function parseJson(text: string): Json | null {
  try {
    const value = JSON.parse(text) as unknown;
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
  } catch {
    return null;
  }
}

function errorMessages(body: Json): string[] {
  const errors = body.errors;
  if (!Array.isArray(errors)) return [];
  return errors.map((e) => (e && typeof e === "object" ? (e as Json).message : undefined)).filter((m): m is string => typeof m === "string");
}

/** Does this JSON look like GraphQL's own answer to `{ __typename }` or to a bad query? */
export function isGraphqlResponse(body: Json | null): boolean {
  if (!body) return false;
  const data = body.data;
  if (data && typeof data === "object" && typeof (data as Json).__typename === "string") return true;
  return errorMessages(body).some((m) => GRAPHQL_ERROR_RE.test(m));
}

/** Number of types in an introspection answer, or null when introspection is not open. */
export function introspectionTypeCount(body: Json | null): number | null {
  const schema = (body?.data as Json | undefined)?.__schema as Json | undefined;
  return Array.isArray(schema?.types) ? schema.types.length : null;
}

export function hasSuggestionLeak(body: Json | null): boolean {
  return body ? errorMessages(body).some((m) => /Did you mean/i.test(m)) : false;
}

type Reply = { ok: true; json: Json | null } | { ok: false };

async function post(url: string, body: string): Promise<Reply> {
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    const text = (await res.text()).slice(0, MAX_BODY_CHARS);
    return { ok: true, json: parseJson(text) };
  } catch {
    return { ok: false };
  }
}

async function getHtml(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { headers: { accept: "text/html" }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (res.status !== 200) {
      await res.body?.cancel();
      return null;
    }
    return (await res.text()).slice(0, MAX_BODY_CHARS);
  } catch {
    return null;
  }
}

export async function checkGraphql(targetUrl: string): Promise<GraphqlResult> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return { status: "error", note: "The target is not a valid web address." };
  }

  const endpoints: GraphqlEndpoint[] = [];
  let unreachable = 0;
  for (const path of GRAPHQL_PATHS) {
    const probe = await post(`${origin}${path}`, TYPENAME_QUERY);
    if (!probe.ok) {
      unreachable++;
      continue;
    }
    if (!isGraphqlResponse(probe.json)) continue;

    const schema = await post(`${origin}${path}`, SCHEMA_QUERY);
    const typeCount = schema.ok ? introspectionTypeCount(schema.json) : null;
    let suggestionsLeak = false;
    if (typeCount === null) {
      const typo = await post(`${origin}${path}`, TYPO_QUERY);
      suggestionsLeak = typo.ok && hasSuggestionLeak(typo.json);
    }
    endpoints.push({ path, introspection: { open: typeCount !== null, typeCount: typeCount ?? 0 }, suggestionsLeak });
  }

  if (unreachable === GRAPHQL_PATHS.length) return { status: "error", note: "The site could not be reached, so GraphQL endpoints were not checked." };

  const ides: string[] = [];
  if (endpoints.length > 0) {
    for (const path of [...IDE_PATHS, ...endpoints.map((e) => e.path)]) {
      const html = await getHtml(`${origin}${path}`);
      if (html && IDE_RE.test(html) && !ides.includes(path)) ides.push(path);
    }
  }

  if (endpoints.length === 0) return { status: "not_applicable" };
  return { status: "checked", endpoints, ides };
}

export function buildGraphqlFindings(result: GraphqlResult | undefined): Finding[] {
  if (result?.status !== "checked") return [];
  const findings: Finding[] = [];
  for (const e of result.endpoints) {
    if (e.introspection.open) {
      findings.push({
        checkId: `graphql.introspection:${e.path}`,
        severity: "medium",
        title: `GraphQL introspection is open at ${e.path}`,
        detail: `Anyone can ask ${e.path} for its whole schema (${e.introspection.typeCount} types were listed): every query, mutation and field name. That is by design for some public APIs, but for an application's own API it hands an attacker a map of what to probe.`,
        remediation: FIX.GRAPHQL_INTROSPECTION,
      });
    } else if (e.suggestionsLeak) {
      findings.push({
        checkId: `graphql.suggestions:${e.path}`,
        severity: "low",
        title: `GraphQL at ${e.path} suggests field names in error messages`,
        detail: `Introspection is off, but a mistyped field is answered with "Did you mean …", which lets an attacker rebuild the schema one guess at a time.`,
        remediation: FIX.GRAPHQL_SUGGESTIONS,
      });
    }
  }
  for (const path of result.ides) {
    findings.push({
      checkId: `graphql.ide:${path}`,
      severity: "low",
      title: `A GraphQL IDE is publicly served at ${path}`,
      detail: `${path} serves an interactive GraphQL explorer (GraphiQL, Playground, Sandbox or similar) to anyone. These are development tools: they make exploring the API trivial for an attacker.`,
      remediation: FIX.GRAPHQL_IDE,
    });
  }
  return findings;
}
