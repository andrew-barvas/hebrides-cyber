// Supabase backend exposure check.
//
// Sites built on Supabase ship the project URL and the public "anon" key in
// their JavaScript — that is by design. What protects the data is row level
// security (RLS). Two mistakes are common and serious:
//   1. a table with RLS off (or a permissive policy) that the anon key can read;
//   2. the service_role key — which bypasses RLS entirely — pasted into
//      client-side code.
//
// This reads only what any visitor's browser already receives: the page's HTML
// and its same-origin scripts. From them it takes the project URL, the keys
// (decoding each JWT's role claim, nothing more) and the table names the code
// itself queries (`.from("name")`). It then asks the project's own REST API
// whether the anon key can read those tables.
//
// Safety and evidence rules (docs/SCANNER-CONVENTIONS.md):
// - Only https://<ref>.supabase.co hosts are ever contacted, only with GET, and
//   only for the project the page itself points at.
// - No table row is ever requested: `?limit=0` with `Prefer: count=exact`
//   returns just the total row count (Content-Range: */N). A table is reported
//   only when that count is above zero — so an RLS-protected table, which
//   answers "0 rows", is never reported, and a table that is empty is not
//   evidence of anything.
// - No key is stored or shown in full: a service_role key is reported by its
//   project reference and a short fingerprint only.
// - Nothing found → "not_applicable" (the site doesn't use Supabase). A page we
//   could not read is "error", never an empty "checked".

export type BackendExposureResult =
  | {
      status: "checked";
      projects: BackendProject[];
    }
  | { status: "not_applicable" }
  | { status: "error"; note: string };

export type BackendProject = {
  /** 20-character Supabase project reference. */
  ref: string;
  url: string;
  /** A service_role key was found in client-delivered code (never stored; fingerprint only). */
  serviceKey: { fingerprint: string; foundIn: string } | null;
  /** Tables the anon key can read rows from, with the count the API reported. */
  openTables: { table: string; rowCount: number }[];
  /** How many candidate tables were asked about. */
  tablesProbed: number;
  /** The table list came from the project's API root; false when only the page's own queries named them. */
  schemaListed: boolean;
};

const PAGE_TIMEOUT_MS = 10_000;
const SCRIPT_TIMEOUT_MS = 10_000;
const PROBE_TIMEOUT_MS = 8_000;
const MAX_SCRIPTS = 12;
const MAX_SCRIPT_CHARS = 2_000_000;
const MAX_TABLES = 25;

const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const FROM_RE = /\.from\(\s*["'`]([a-z_][a-z0-9_]{0,62})["'`]\s*\)/g;
const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;

type Source = { label: string; text: string };

/** The claims of a JWT's payload, or null. Not verified — we only read the role. */
export function decodeJwtClaims(token: string): { role?: string; ref?: string; iss?: string } | null {
  try {
    const payload = token.split(".")[1];
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const claims = JSON.parse(json) as Record<string, unknown>;
    return {
      role: typeof claims.role === "string" ? claims.role : undefined,
      ref: typeof claims.ref === "string" ? claims.ref : undefined,
      iss: typeof claims.iss === "string" ? claims.iss : undefined,
    };
  } catch {
    return null;
  }
}

/** First and last few characters, enough to recognise the key without reproducing it. */
export function keyFingerprint(token: string): string {
  return `${token.slice(0, 6)}…${token.slice(-4)}`;
}

export type Discovered = {
  refs: string[];
  anonKeys: Map<string, string>; // ref → key
  serviceKeys: Map<string, { key: string; foundIn: string }>; // ref → key
  tables: string[];
};

/** Pure: Supabase project refs, keys and queried table names found in page text. */
export function discoverBackends(sources: Source[]): Discovered {
  const refs = new Set<string>();
  const anonKeys = new Map<string, string>();
  const serviceKeys = new Map<string, { key: string; foundIn: string }>();
  const tables = new Set<string>();

  for (const { label, text } of sources) {
    for (const m of text.matchAll(SUPABASE_URL_RE)) refs.add(m[1]);
    for (const m of text.matchAll(FROM_RE)) tables.add(m[1]);
    for (const m of text.matchAll(JWT_RE)) {
      const claims = decodeJwtClaims(m[0]);
      if (!claims || claims.iss !== "supabase" || !claims.ref || !/^[a-z0-9]{20}$/.test(claims.ref)) continue;
      refs.add(claims.ref);
      if (claims.role === "service_role") serviceKeys.set(claims.ref, { key: m[0], foundIn: label });
      else if (claims.role === "anon" && !anonKeys.has(claims.ref)) anonKeys.set(claims.ref, m[0]);
    }
  }
  return { refs: [...refs], anonKeys, serviceKeys, tables: [...tables] };
}

/** Table names listed by PostgREST's OpenAPI root (paths other than "/" and "/rpc/…"). */
export function tablesFromOpenApi(doc: unknown): string[] {
  const paths = (doc as { paths?: Record<string, unknown> } | null)?.paths;
  if (!paths || typeof paths !== "object") return [];
  return Object.keys(paths)
    .filter((p) => /^\/[a-z_][a-z0-9_]*$/i.test(p))
    .map((p) => p.slice(1));
}

async function fetchText(url: string, timeoutMs: number, maxChars: number): Promise<{ ok: boolean; status: number; text: string }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: "follow" });
  const text = res.ok ? (await res.text()).slice(0, maxChars) : "";
  if (!res.ok) await res.body?.cancel();
  return { ok: res.ok, status: res.status, text };
}

/** Content-Range "*\/N" or "0-0\/N" → N. */
export function totalFromContentRange(header: string | null): number | null {
  const m = header?.match(/\/(\d+)$/);
  return m ? Number(m[1]) : null;
}

async function probeProject(ref: string, anonKey: string | undefined, hintedTables: string[]): Promise<Pick<BackendProject, "openTables" | "tablesProbed" | "schemaListed">> {
  if (!anonKey) return { openTables: [], tablesProbed: 0, schemaListed: false };
  const base = `https://${ref}.supabase.co/rest/v1`;
  const headers = { apikey: anonKey, authorization: `Bearer ${anonKey}` };

  // The API root lists the schema where the project allows it; otherwise only the page's own queries name tables.
  let listed: string[] = [];
  let schemaListed = false;
  try {
    const root = await fetch(`${base}/`, { headers: { ...headers, accept: "application/openapi+json" }, signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    if (root.ok) {
      listed = tablesFromOpenApi(await root.json().catch(() => null));
      schemaListed = listed.length > 0;
    } else {
      await root.body?.cancel();
    }
  } catch {
    // root unreachable — fall back to the page's own table names
  }

  const candidates = [...new Set([...listed, ...hintedTables])].slice(0, MAX_TABLES);
  const openTables: { table: string; rowCount: number }[] = [];
  for (const table of candidates) {
    try {
      const res = await fetch(`${base}/${encodeURIComponent(table)}?select=*&limit=0`, {
        headers: { ...headers, prefer: "count=exact" },
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      await res.body?.cancel();
      const total = totalFromContentRange(res.headers.get("content-range"));
      if ((res.status === 200 || res.status === 206) && total !== null && total > 0) openTables.push({ table, rowCount: total });
    } catch {
      // unreachable table probe: nothing evidenced
    }
  }
  return { openTables, tablesProbed: candidates.length, schemaListed };
}

export async function checkBackendExposure(targetUrl: string): Promise<BackendExposureResult> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return { status: "error", note: "The target is not a valid web address." };
  }

  let page: { ok: boolean; status: number; text: string };
  try {
    page = await fetchText(targetUrl, PAGE_TIMEOUT_MS, MAX_SCRIPT_CHARS);
  } catch (err) {
    return { status: "error", note: `Could not read the page: ${(err as Error).message}` };
  }
  if (!page.ok) return { status: "error", note: `The page returned HTTP ${page.status}, so its scripts were not read.` };

  const sources: Source[] = [{ label: targetUrl, text: page.text }];
  const scriptUrls: string[] = [];
  for (const m of page.text.matchAll(SCRIPT_SRC_RE)) {
    try {
      const u = new URL(m[1], targetUrl);
      if (u.origin === origin && !scriptUrls.includes(u.href)) scriptUrls.push(u.href);
    } catch {
      // not a URL
    }
  }
  for (const url of scriptUrls.slice(0, MAX_SCRIPTS)) {
    try {
      const s = await fetchText(url, SCRIPT_TIMEOUT_MS, MAX_SCRIPT_CHARS);
      if (s.ok) sources.push({ label: url, text: s.text });
    } catch {
      // a script we couldn't read just contributes nothing
    }
  }

  const found = discoverBackends(sources);
  if (found.refs.length === 0) return { status: "not_applicable" };

  const projects: BackendProject[] = [];
  for (const ref of found.refs.slice(0, 3)) {
    const service = found.serviceKeys.get(ref);
    const probe = await probeProject(ref, found.anonKeys.get(ref), found.tables);
    projects.push({
      ref,
      url: `https://${ref}.supabase.co`,
      serviceKey: service ? { fingerprint: keyFingerprint(service.key), foundIn: service.foundIn } : null,
      ...probe,
    });
  }
  return { status: "checked", projects };
}
