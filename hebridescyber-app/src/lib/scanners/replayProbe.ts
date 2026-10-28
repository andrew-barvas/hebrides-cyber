// Bounded request replay: the safe, scanner-side analogue of a manual tester's
// "repeater". Something (a deterministic validator, or the AI triage step in
// aiTriage.ts) asks for one specific read-only request against the target and
// gets back what the server actually said. It can never be asked to do
// anything else, because every request goes through the allowlist below:
//
//   - GET / HEAD only, no request body.
//   - The path must be same-origin (absolute path, no scheme, no `//host`), and
//     the resolved host must belong to the same owner domain as the target.
//   - Redirects are never followed; the Location is reported, not visited.
//   - Only a short list of harmless request headers may be set (no cookies or
//     credentials), and Set-Cookie values are redacted from the capture.
//   - Every call spends from a per-scan budget, so a caller that loops cannot
//     send more than the cap, however many findings there are.
//
// A failure is `status: "error"` and a policy rejection is `status: "refused"`;
// neither is ever an empty "ok" (CLAUDE.md rule 7), so a caller cannot read a
// failed lookup as "nothing found".
import { isCatchAllBody, normaliseBody, type Baseline } from "./httpProbe";
import { isWithinDomain, ownerDomain } from "./registrableDomain";

const REQUEST_TIMEOUT_MS = 8_000;
/** Most of a response kept as evidence; enough to quote, small enough to store and prompt with. */
export const MAX_REPLAY_BODY_BYTES = 16_384;
/** Default cap on replays per scan, shared by every caller via one budget. */
export const MAX_REPLAYS_PER_SCAN = 20;
const MAX_PATH_LENGTH = 512;
const MAX_QUERY_PARAMS = 10;
const MAX_VALUE_LENGTH = 256;

/** Request headers a replay may set. Deliberately excludes Cookie/Authorization/Host. */
const ALLOWED_REQUEST_HEADERS = new Set(["accept", "accept-language", "origin", "referer", "user-agent"]);

export type ReplaySpec = {
  method?: "GET" | "HEAD";
  /** Absolute path on the target, e.g. "/search". */
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
};

export type ReplayBudget = { remaining: number };

export function createReplayBudget(max: number = MAX_REPLAYS_PER_SCAN): ReplayBudget {
  return { remaining: Math.max(0, Math.floor(max)) };
}

export type ReplayCapture = {
  /** Human-readable request line plus the headers that were sent. */
  request: string;
  response: {
    status: number;
    headers: Record<string, string>;
    /** At most MAX_REPLAY_BODY_BYTES of the body. */
    body: string;
    truncated: boolean;
  };
  /** True when a baseline was given and this 200 body is the site's catch-all shell. */
  catchAll: boolean;
  /** Redirect target, reported but never followed. */
  redirectTo?: string;
};

export type ReplayResult =
  | ({ status: "ok" } & ReplayCapture)
  | { status: "refused"; reason: string }
  | { status: "error"; message: string };

export type ReplayOptions = {
  budget: ReplayBudget;
  /** From httpProbe.fetchBaseline; lets the replay flag a catch-all response. */
  baseline?: Baseline;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
};

function refuse(reason: string): ReplayResult {
  return { status: "refused", reason };
}

/** Validate a spec and resolve it to a URL on the target, or say why not. */
export function resolveReplayUrl(targetUrl: string, spec: ReplaySpec): { url: URL } | { reason: string } {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return { reason: "target URL is not valid" };
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") return { reason: "target is not http(s)" };

  const path = spec.path;
  if (typeof path !== "string" || !path.startsWith("/")) return { reason: "path must be an absolute path starting with /" };
  if (path.startsWith("//") || path.includes("\\")) return { reason: "path must not name another host" };
  if (path.length > MAX_PATH_LENGTH) return { reason: "path is too long" };
  if (/[\u0000-\u001f\u007f]/.test(path)) return { reason: "path contains control characters" };

  let url: URL;
  try {
    url = new URL(path, target.origin);
  } catch {
    return { reason: "path is not valid" };
  }

  const entries = Object.entries(spec.query ?? {});
  if (entries.length > MAX_QUERY_PARAMS) return { reason: "too many query parameters" };
  for (const [k, v] of entries) {
    if (typeof v !== "string" || k.length > MAX_VALUE_LENGTH || v.length > MAX_VALUE_LENGTH) {
      return { reason: "query parameter is too long" };
    }
    url.searchParams.set(k, v);
  }

  const owner = ownerDomain(target.hostname);
  // IP-address and localhost targets have no owner domain: they may only replay against the exact host.
  const sameSite = owner ? isWithinDomain(url.hostname, owner) : url.hostname === target.hostname;
  if (url.origin !== target.origin && !sameSite) return { reason: "request leaves the target's domain" };
  return { url };
}

function sanitiseRequestHeaders(headers: Record<string, string> | undefined): { ok: Record<string, string> } | { reason: string } {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) return { reason: `request header "${name}" is not allowed` };
    if (typeof value !== "string" || value.length > MAX_VALUE_LENGTH || /[\r\n]/.test(value)) {
      return { reason: `request header "${name}" has an invalid value` };
    }
    out[name] = value;
  }
  return { ok: out };
}

function captureHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  const forEach = (res.headers as { forEach?: (cb: (v: string, k: string) => void) => void }).forEach;
  if (typeof forEach === "function") {
    forEach.call(res.headers, (value: string, name: string) => {
      const key = name.toLowerCase();
      // Cookie values are credentials in waiting; keep only that one was set.
      out[key] = key === "set-cookie" ? "[redacted]" : value.slice(0, MAX_VALUE_LENGTH * 2);
    });
  }
  return out;
}

async function readCapped(res: Response): Promise<{ body: string; truncated: boolean }> {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return { body: text.slice(0, MAX_REPLAY_BODY_BYTES), truncated: text.length > MAX_REPLAY_BODY_BYTES };
  }
  const decoder = new TextDecoder();
  let body = "";
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    body += decoder.decode(value, { stream: true });
    if (body.length > MAX_REPLAY_BODY_BYTES) {
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
  }
  return { body: body.slice(0, MAX_REPLAY_BODY_BYTES), truncated };
}

/** Send one allowlisted, read-only request and return what came back. */
export async function replayProbe(targetUrl: string, spec: ReplaySpec, options: ReplayOptions): Promise<ReplayResult> {
  const method = spec.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") return refuse("only GET and HEAD are allowed");

  const resolved = resolveReplayUrl(targetUrl, spec);
  if ("reason" in resolved) return refuse(resolved.reason);
  const headers = sanitiseRequestHeaders(spec.headers);
  if ("reason" in headers) return refuse(headers.reason);

  if (options.budget.remaining <= 0) return refuse("replay budget for this scan is spent");
  options.budget.remaining--;

  const doFetch = options.fetchImpl ?? fetch;
  const { url } = resolved;
  try {
    const res = await doFetch(url.href, {
      method,
      headers: headers.ok,
      redirect: "manual",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const { body, truncated } = method === "HEAD" ? { body: "", truncated: false } : await readCapped(res);
    const location = res.headers.get("location") ?? undefined;
    const catchAll =
      res.status === 200 && options.baseline ? isCatchAllBody(options.baseline, normaliseBody(body, url.pathname)) : false;

    const sent = Object.entries(headers.ok).map(([k, v]) => `${k}: ${v}`);
    return {
      status: "ok",
      request: [`${method} ${url.pathname}${url.search}`, ...sent].join("\n"),
      response: { status: res.status, headers: captureHeaders(res), body, truncated },
      catchAll,
      redirectTo: location,
    };
  } catch (err) {
    return { status: "error", message: (err as Error).message };
  }
}
