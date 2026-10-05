import type { Page, Route } from "@playwright/test";
import { TEST_USER } from "./session";

// Network mocks for the signed-in app. Two layers, both browser-side:
//
//  1. mockSupabase(): the browser's PostgREST calls to
//     https://example-project.supabase.co/rest/v1/<table>. Each table is a
//     fixed row list (or a function of the request URL), run through a tiny
//     PostgREST-style filter (eq/neq/lt/in, order, limit/offset) so queries
//     like "other scans of this host" behave the way the real database would.
//  2. mockApi(): same-origin /api/* routes. Anything NOT explicitly mocked is
//     answered 501 and recorded, so a test can never reach a real handler
//     (which would call the real Supabase) and an unexpected call is visible.
//
// The server-side half (middleware's auth.getUser()) cannot be mocked from the
// browser — see supabase-auth-preload.cjs.

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "*",
  "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
};

type Row = Record<string, unknown>;
export type TableMock = Row[] | ((url: URL) => Row[] | Row | null);

export function applyQuery(rows: Row[], url: URL): Row[] {
  let out = rows;
  for (const [key, raw] of url.searchParams) {
    if (["select", "order", "limit", "offset", "on_conflict", "columns"].includes(key)) continue;
    const dot = raw.indexOf(".");
    const op = raw.slice(0, dot);
    const value = raw.slice(dot + 1);
    if (op === "eq") out = out.filter((r) => String(r[key]) === value);
    else if (op === "neq") out = out.filter((r) => String(r[key]) !== value);
    else if (op === "lt") out = out.filter((r) => String(r[key]) < value);
    else if (op === "in") out = out.filter((r) => value.replace(/^\(|\)$/g, "").split(",").includes(String(r[key])));
    // Other operators (not/is/ilike...) are deliberately ignored: fixtures
    // are small, and a filter we don't model should not silently drop rows.
  }
  const order = url.searchParams.get("order");
  if (order) {
    const [col, dir] = order.split(".");
    out = [...out].sort((a, b) => String(a[col]).localeCompare(String(b[col])) * (dir === "desc" ? -1 : 1));
  }
  const offset = Number(url.searchParams.get("offset") ?? 0);
  const limit = url.searchParams.get("limit");
  return out.slice(offset, limit ? offset + Number(limit) : undefined);
}

/** Mocks Supabase REST (and the auth endpoints the browser client may call).
 *  Tables that aren't listed answer with an empty list. */
export async function mockSupabase(page: Page, tables: Record<string, TableMock>): Promise<void> {
  await page.route("https://example-project.supabase.co/**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "OPTIONS") return route.fulfill({ status: 204, headers: CORS });

    if (url.pathname === "/auth/v1/user") {
      return route.fulfill({
        status: 200,
        headers: CORS,
        json: { id: TEST_USER.id, aud: "authenticated", role: "authenticated", email: TEST_USER.email, app_metadata: {}, user_metadata: {} },
      });
    }

    const match = url.pathname.match(/^\/rest\/v1\/([^/]+)$/);
    if (!match) return route.fulfill({ status: 404, headers: CORS, json: { message: "not mocked" } });

    const mock = tables[match[1]];
    const result = typeof mock === "function" ? mock(url) : mock ? applyQuery(mock, url) : [];
    const rows = result === null ? [] : Array.isArray(result) ? result : [result];
    const wantsObject = (request.headers()["accept"] ?? "").includes("vnd.pgrst.object");
    if (wantsObject) {
      return route.fulfill(
        rows.length === 1
          ? { status: 200, headers: CORS, json: rows[0] }
          : { status: 406, headers: CORS, json: { code: "PGRST116", message: "JSON object requested, multiple (or no) rows returned" } }
      );
    }
    return route.fulfill({ status: 200, headers: CORS, json: rows });
  });
}

export type ApiCall = { method: string; path: string; body: unknown; authorization: string | undefined };
type ApiHandler = (call: ApiCall) => { status?: number; json: unknown };

export type ApiMock = {
  /** Every /api/* request the page made, in order (mocked or not). */
  calls: ApiCall[];
  /** Calls matching a method + path, e.g. calls.to("PUT", "/api/findings/triage"). */
  to: (method: string, path: string) => ApiCall[];
};

/** Mocks same-origin API routes. `handlers` keys are "METHOD /api/path"
 *  (query string ignored); a handler may inspect the call to vary its answer. */
export async function mockApi(page: Page, handlers: Record<string, ApiHandler | { status?: number; json: unknown }>): Promise<ApiMock> {
  const calls: ApiCall[] = [];
  await page.route("**/api/**", async (route: Route) => {
    const request = route.request();
    // Only XHR/fetch: a document navigation to /api/... is not something the
    // app does, and must not be swallowed.
    if (!["fetch", "xhr"].includes(request.resourceType())) return route.fallback();
    const url = new URL(request.url());
    let body: unknown = null;
    const raw = request.postData();
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }
    const call: ApiCall = { method: request.method(), path: url.pathname, body, authorization: request.headers()["authorization"] };
    calls.push(call);
    const handler = handlers[`${call.method} ${call.path}`];
    if (!handler) return route.fulfill({ status: 501, json: { error: `unmocked e2e API call: ${call.method} ${call.path}` } });
    const { status = 200, json } = typeof handler === "function" ? handler(call) : handler;
    return route.fulfill({ status, json });
  });
  return { calls, to: (method, path) => calls.filter((c) => c.method === method && c.path === path) };
}
