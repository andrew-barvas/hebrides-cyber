// Microsoft Graph access for the Microsoft 365 / Entra ID posture checks
// (P1-4, src/lib/scanners/m365Posture.ts) and the admin-consent callback
// (src/pages/api/account/m365-callback.ts).
//
// We hold no customer secret. The customer's admin consents our multi-tenant
// Entra app into their tenant; after that we ask Microsoft for an app-only
// token FOR THAT TENANT with our own credential (OAuth 2.0 client
// credentials, M365_CLIENT_ID / M365_CLIENT_SECRET from the environment).
// The token is used for the one scan and never stored. If the admin removes
// our app from the tenant, the token request fails and the checks report
// status "error" — never a clean result.
//
// No SDK: four GET endpoints and one token POST are plain fetch, the same
// choice cloudPosture.ts made for AWS/GCP. `fetchImpl` is injectable so unit
// tests can replay recorded or hand-built Graph JSON without a tenant.

export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const LOGIN_BASE = "https://login.microsoftonline.com";
const REQUEST_TIMEOUT_MS = 15_000;

/** Graph application permissions the app registration must request (and the admin consents). */
export const M365_REQUIRED_APP_ROLES = [
  "Policy.Read.All",
  "Directory.Read.All",
  "Reports.Read.All",
  "MailboxSettings.Read",
  "AuditLog.Read.All",
] as const;

export type M365AppConfig = { clientId: string; clientSecret: string };

/** process.env, or a plain object in tests. */
export type Env = Record<string, string | undefined>;

/** Our app registration's credential, or null when this deployment hasn't been given one. */
export function m365AppConfig(env: Env = process.env): M365AppConfig | null {
  const clientId = env.M365_CLIENT_ID?.trim();
  const clientSecret = env.M365_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function isTenantId(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export type GraphError = { status: number; code: string; message: string };
export type GraphResult<T> = { ok: true; body: T } | { ok: false; error: GraphError };

export type AppToken = { accessToken: string; roles: string[]; tenantId: string | null };

/** Reads the `roles` and `tid` claims. The token came straight from Microsoft over TLS, so no signature check is needed here. */
export function decodeTokenClaims(accessToken: string): { roles: string[]; tid: string | null } {
  try {
    const payload = accessToken.split(".")[1];
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { roles?: unknown; tid?: unknown };
    const roles = Array.isArray(json.roles) ? json.roles.filter((r): r is string => typeof r === "string") : [];
    return { roles, tid: typeof json.tid === "string" ? json.tid : null };
  } catch {
    return { roles: [], tid: null };
  }
}

/** App-only Graph token for `tenantId`. Fails when the tenant never consented or has since removed our app. */
export async function getAppToken(
  tenantId: string,
  config: M365AppConfig,
  fetchImpl: typeof fetch = fetch
): Promise<GraphResult<AppToken>> {
  if (!isTenantId(tenantId)) return { ok: false, error: { status: 400, code: "invalid_tenant", message: "Tenant ID is not a GUID" } };
  try {
    const res = await fetchImpl(`${LOGIN_BASE}/${tenantId}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      }).toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const body = (await res.json().catch(() => ({}))) as { access_token?: string; error?: string; error_description?: string };
    if (!res.ok || !body.access_token) {
      // error_description carries an AADSTS code (e.g. AADSTS700016: app not
      // found in the tenant) — useful in the scan note, never secret.
      const code = body.error ?? `http_${res.status}`;
      const aadsts = body.error_description?.match(/AADSTS\d+/)?.[0];
      return { ok: false, error: { status: res.status, code, message: aadsts ? `${code} (${aadsts})` : code } };
    }
    const claims = decodeTokenClaims(body.access_token);
    return { ok: true, body: { accessToken: body.access_token, roles: claims.roles, tenantId: claims.tid } };
  } catch (err) {
    return { ok: false, error: { status: 0, code: "network_error", message: (err as Error).message } };
  }
}

export type GraphClient = {
  /** One GET. `path` is relative to GRAPH_BASE ("/policies/authorizationPolicy"). */
  get<T>(path: string): Promise<GraphResult<T>>;
  /** GET a collection and follow @odata.nextLink up to `maxItems`; `truncated` says whether more were left. */
  getAll<T>(path: string, maxItems: number): Promise<GraphResult<{ items: T[]; truncated: boolean }>>;
};

export function createGraphClient(accessToken: string, fetchImpl: typeof fetch = fetch): GraphClient {
  async function getUrl<T>(url: string): Promise<GraphResult<T>> {
    try {
      const res = await fetchImpl(url, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const body = (await res.json().catch(() => null)) as unknown;
      if (!res.ok) {
        const err = (body as { error?: { code?: string; message?: string } } | null)?.error;
        return { ok: false, error: { status: res.status, code: err?.code ?? `http_${res.status}`, message: err?.message ?? `HTTP ${res.status}` } };
      }
      return { ok: true, body: body as T };
    } catch (err) {
      return { ok: false, error: { status: 0, code: "network_error", message: (err as Error).message } };
    }
  }

  return {
    get: <T>(path: string) => getUrl<T>(`${GRAPH_BASE}${path}`),
    async getAll<T>(path: string, maxItems: number) {
      const items: T[] = [];
      let next: string | undefined = `${GRAPH_BASE}${path}`;
      while (next) {
        const page: GraphResult<{ value?: T[]; "@odata.nextLink"?: string }> = await getUrl(next);
        if (!page.ok) return page;
        for (const item of page.body.value ?? []) {
          if (items.length >= maxItems) return { ok: true, body: { items, truncated: true } };
          items.push(item);
        }
        next = page.body["@odata.nextLink"];
        // Only ever follow Graph's own links: a nextLink is server-supplied data.
        if (next && !next.startsWith(`${GRAPH_BASE}/`)) return { ok: false, error: { status: 0, code: "bad_next_link", message: "Unexpected @odata.nextLink host" } };
      }
      return { ok: true, body: { items, truncated: false } };
    },
  };
}
