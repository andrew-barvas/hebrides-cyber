import { describe, it, expect, vi, afterEach } from "vitest";
import {
  checkBackendExposure,
  decodeJwtClaims,
  discoverBackends,
  keyFingerprint,
  tablesFromOpenApi,
  totalFromContentRange,
} from "./backendExposure";
import { summariseResults, type ScanResults } from "./index";

afterEach(() => {
  vi.unstubAllGlobals();
});

const REF = "abcdefghijklmnopqrst";
const OTHER_REF = "uvwxyzabcdefghijklmn";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon" });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role" });

describe("helpers", () => {
  it("decodes a JWT's claims without trusting them, and rejects junk", () => {
    expect(decodeJwtClaims(ANON)).toEqual({ role: "anon", ref: REF, iss: "supabase" });
    expect(decodeJwtClaims(jwt({ role: 5, ref: 1, iss: null }))).toEqual({ role: undefined, ref: undefined, iss: undefined });
    expect(decodeJwtClaims("not.a.jwt")).toBeNull();
    expect(decodeJwtClaims("x")).toBeNull();
  });

  it("fingerprints a key without reproducing it", () => {
    const fp = keyFingerprint(SERVICE);
    expect(fp).toHaveLength(11);
    expect(fp).toContain("…");
    expect(SERVICE.includes(fp.replace("…", ""))).toBe(false);
  });

  it("reads the total from Content-Range", () => {
    expect(totalFromContentRange("*/12")).toBe(12);
    expect(totalFromContentRange("0-0/3")).toBe(3);
    expect(totalFromContentRange("*/*")).toBeNull();
    expect(totalFromContentRange(null)).toBeNull();
  });

  it("lists table names from PostgREST's OpenAPI root, not rpc or the root path", () => {
    expect(tablesFromOpenApi({ paths: { "/": {}, "/profiles": {}, "/rpc/do_thing": {}, "/orders": {} } })).toEqual(["profiles", "orders"]);
    expect(tablesFromOpenApi(null)).toEqual([]);
    expect(tablesFromOpenApi({})).toEqual([]);
    expect(tablesFromOpenApi("nope")).toEqual([]);
  });
});

describe("discoverBackends", () => {
  it("finds project refs, anon and service keys, and the tables the code queries", () => {
    const found = discoverBackends([
      { label: "page", text: `const url = "https://${REF}.supabase.co"; const k = "${ANON}"; supabase.from("profiles").select()` },
      { label: "bundle.js", text: `x.from('orders'); y.from(\`items\`); const s = "${SERVICE}"; fetch("https://${OTHER_REF}.supabase.co")` },
    ]);
    expect(found.refs.sort()).toEqual([REF, OTHER_REF].sort());
    expect(found.anonKeys.get(REF)).toBe(ANON);
    expect(found.serviceKeys.get(REF)).toEqual({ key: SERVICE, foundIn: "bundle.js" });
    expect(found.tables.sort()).toEqual(["items", "orders", "profiles"]);
  });

  it("ignores JWTs that aren't Supabase's, with a bad ref, or an unknown role; keeps the first anon key", () => {
    const found = discoverBackends([
      {
        label: "p",
        text: [
          jwt({ iss: "auth0", ref: REF, role: "anon" }),
          jwt({ iss: "supabase", ref: "short", role: "anon" }),
          jwt({ iss: "supabase", role: "anon" }),
          jwt({ iss: "supabase", ref: REF, role: "authenticated" }),
          ANON,
          jwt({ iss: "supabase", ref: REF, role: "anon", extra: 1 }),
          "eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.garbage-signature",
        ].join(" "),
      },
    ]);
    expect(found.refs).toEqual([REF]);
    expect(found.anonKeys.get(REF)).toBe(ANON);
    expect(found.serviceKeys.size).toBe(0);
  });

  it("finds nothing on a page with no Supabase", () => {
    expect(discoverBackends([{ label: "p", text: "<html>hello</html>" }])).toEqual({ refs: [], anonKeys: new Map(), serviceKeys: new Map(), tables: [], buckets: [] });
  });

  it("treats .storage.from(\"x\") as a bucket, not a table, and caps buckets", () => {
    const found = discoverBackends([
      { label: "p", text: `supabase.storage.from("avatars").list(); supabase.storage .from('invoices'); db.from("profiles"); ${["a1", "b2", "c3", "d4", "e5", "f6"].map((b) => `s.storage.from("${b}")`).join(";")}` },
    ]);
    expect(found.tables).toEqual(["profiles"]);
    expect(found.buckets).toEqual(["avatars", "invoices", "a1", "b2", "c3"]);
  });
});

type Route = { status?: number; body?: string; headers?: Record<string, string> };

/** Stubs fetch with the site and a Supabase project; records every request. */
function stub(routes: Record<string, Route | (() => never)>) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, headers: (init?.headers ?? {}) as Record<string, string> });
      const route = routes[url];
      if (typeof route === "function") return route();
      if (!route) return new Response("not found", { status: 404 });
      return new Response(route.body ?? "", { status: route.status ?? 200, headers: route.headers });
    })
  );
  return calls;
}
const boom = (): never => {
  throw new Error("network down");
};

const SITE = "https://shop.example";
const API = `https://${REF}.supabase.co/rest/v1`;
const pageWith = () => `<html><script src="/app.js"></script><script src="https://cdn.other/x.js"></script><script src="/app.js"></script><script src="http://[bad"></script></html>`;

describe("checkBackendExposure", () => {
  it("reports tables the anon key can read, by count only, and not RLS-protected or unreachable ones", async () => {
    const calls = stub({
      [`${SITE}/`]: { body: pageWith() },
      [`${SITE}/app.js`]: { body: `createClient("https://${REF}.supabase.co", "${ANON}"); db.from("profiles"); db.from("secrets"); db.from("hidden")` },
      [`${API}/`]: { body: JSON.stringify({ paths: { "/": {}, "/profiles": {}, "/orders": {}, "/secrets": {} } }) },
      [`${API}/profiles?select=*&limit=0`]: { status: 206, headers: { "content-range": "*/2" } },
      [`${API}/orders?select=*&limit=0`]: { status: 401 },
      [`${API}/secrets?select=*&limit=0`]: { status: 200, headers: { "content-range": "*/0" } },
      [`${API}/hidden?select=*&limit=0`]: { status: 200 },
    });
    const result = await checkBackendExposure(`${SITE}/`);
    expect(result).toEqual({
      status: "checked",
      projects: [{ ref: REF, url: `https://${REF}.supabase.co`, serviceKey: null, openTables: [{ table: "profiles", rowCount: 2 }], tablesProbed: 4, schemaListed: true, openBuckets: [], bucketsProbed: 0 }],
    });
    // Only row counts were asked for — no row data — and only the project's own host was contacted.
    const probes = calls.filter((c) => c.url.startsWith(API) && c.url !== `${API}/`);
    expect(probes.length).toBe(4);
    for (const p of probes) {
      expect(p.url).toContain("limit=0");
      expect(p.headers.prefer).toBe("count=exact");
      expect(p.headers.apikey).toBe(ANON);
    }
    expect(calls.every((c) => c.url.startsWith(SITE) || c.url.startsWith(`https://${REF}.supabase.co/`))).toBe(true);
    expect(calls.some((c) => c.url.includes("cdn.other"))).toBe(false);
  });

  it("falls back to the tables the page's own code queries when the schema can't be listed", async () => {
    stub({
      [`${SITE}/`]: { body: `<script>const k="${ANON}"; db.from("notes")</script>` },
      [`${API}/`]: { status: 401 },
      [`${API}/notes?select=*&limit=0`]: { status: 206, headers: { "content-range": "0-0/9" } },
    });
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects[0]).toMatchObject({ schemaListed: false, tablesProbed: 1, openTables: [{ table: "notes", rowCount: 9 }] });
  });

  it("survives an unreadable schema root, a non-JSON root and a failing probe", async () => {
    stub({
      [`${SITE}/`]: { body: `<script>const k="${ANON}"; db.from("a"); db.from("b")</script>` },
      [`${API}/`]: { body: "not json" },
      [`${API}/a?select=*&limit=0`]: boom,
      [`${API}/b?select=*&limit=0`]: { status: 206, headers: { "content-range": "*/1" } },
    });
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects[0]).toMatchObject({ schemaListed: false, tablesProbed: 2, openTables: [{ table: "b", rowCount: 1 }] });
    stub({ [`${SITE}/`]: { body: `<script>const k="${ANON}"; db.from("a")</script>` }, [`${API}/`]: boom, [`${API}/a?select=*&limit=0`]: { status: 200 } });
    const down = await checkBackendExposure(`${SITE}/`);
    if (down.status !== "checked") throw new Error("unexpected");
    expect(down.projects[0].openTables).toEqual([]);
  });

  it("reports a service_role key by fingerprint only, even with no anon key to probe with", async () => {
    stub({ [`${SITE}/`]: { body: `<script src="/app.js"></script>` }, [`${SITE}/app.js`]: { body: `const k = "${SERVICE}"` } });
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects[0].serviceKey).toEqual({ fingerprint: keyFingerprint(SERVICE), foundIn: `${SITE}/app.js` });
    expect(result.projects[0]).toMatchObject({ openTables: [], tablesProbed: 0, schemaListed: false });
    expect(JSON.stringify(result)).not.toContain(SERVICE);
  });

  it("is not_applicable when the page doesn't use Supabase, and ignores a script that fails to load", async () => {
    stub({ [`${SITE}/`]: { body: `<script src="/broken.js"></script><script src="/gone.js"></script>` }, [`${SITE}/broken.js`]: boom });
    expect(await checkBackendExposure(`${SITE}/`)).toEqual({ status: "not_applicable" });
  });

  it("is an error, never a clean result, when the page can't be read", async () => {
    stub({ [`${SITE}/`]: { status: 500 } });
    expect(await checkBackendExposure(`${SITE}/`)).toMatchObject({ status: "error", note: expect.stringContaining("HTTP 500") });
    stub({ [`${SITE}/`]: boom });
    expect(await checkBackendExposure(`${SITE}/`)).toMatchObject({ status: "error", note: expect.stringContaining("network down") });
    expect(await checkBackendExposure("not a url")).toMatchObject({ status: "error" });
  });

  it("reports a bucket only when the anon key lists a file from it, asking for one name", async () => {
    const STORAGE = `https://${REF}.supabase.co/storage/v1/object/list`;
    const calls: { url: string; method: string; body: string }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, method: init?.method ?? "GET", body: String(init?.body ?? "") });
        if (url === `${SITE}/`) return new Response(`<script>const k="${ANON}"; s.storage.from("avatars"); s.storage.from("private"); s.storage.from("broken"); s.storage.from("down")</script>`);
        if (url === `${STORAGE}/avatars`) return new Response(JSON.stringify([{ name: "me.png" }]));
        if (url === `${STORAGE}/private`) return new Response("[]");
        if (url === `${STORAGE}/broken`) return new Response("not json", { status: 400 });
        if (url === `${STORAGE}/down`) throw new Error("network down");
        return new Response("", { status: 404 });
      })
    );
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects[0]).toMatchObject({ openBuckets: [{ bucket: "avatars" }], bucketsProbed: 4 });
    const lists = calls.filter((c) => c.url.startsWith(STORAGE));
    expect(lists).toHaveLength(4);
    for (const c of lists) {
      expect(c.method).toBe("POST");
      expect(JSON.parse(c.body)).toEqual({ prefix: "", limit: 1 });
    }
  });

  it("checks Firebase from the same page material, even with no Supabase", async () => {
    stub({
      [`${SITE}/`]: { body: `<script src="/app.js"></script>` },
      [`${SITE}/app.js`]: { body: `initializeApp({databaseURL:"https://shop-default-rtdb.firebaseio.com",projectId:"shop-app"})` },
      ["https://shop-default-rtdb.firebaseio.com/.json?shallow=true"]: { body: JSON.stringify({ users: true }) },
    });
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects).toEqual([]);
    expect(result.firebase?.open).toEqual([{ kind: "rtdb", url: "https://shop-default-rtdb.firebaseio.com", keyCount: 1 }]);
    expect(result.firebase?.targets.projects).toEqual(["shop-app"]);
  });

  it("caps projects and tables", async () => {
    const refs = ["a", "b", "c", "d"].map((c) => c.repeat(20));
    const tables = Array.from({ length: 40 }, (_, i) => `t${i}`);
    stub({ [`${SITE}/`]: { body: `<script>${refs.map((r) => `"https://${r}.supabase.co"`).join(";")}; ${tables.map((t) => `x.from("${t}")`).join(";")}; k="${ANON}"</script>` } });
    const result = await checkBackendExposure(`${SITE}/`);
    if (result.status !== "checked") throw new Error("unexpected");
    expect(result.projects).toHaveLength(3);
    expect(result.projects.find((p) => p.ref === REF)?.tablesProbed ?? 0).toBeLessThanOrEqual(25);
  });
});

function results(backendExposure: ScanResults["backendExposure"]): ScanResults {
  const err = { status: "error", note: "x" };
  return {
    target_url: "https://shop.example", checked_at: "2026-10-05T00:00:00Z",
    tls: err, headers: err, dns: err, exposure: err, directoryListing: err, cloudMisconfig: err, fingerprint: err, ports: err,
    playwright: err, recon: err, webapp: err, safeBrowsing: err, waybackDiscovery: err, hibp: err, wpVulnDb: err, softwareCveDb: err,
    businessLogic: err, apiSpec: err, zap: err, backendExposure,
  } as unknown as ScanResults;
}

describe("backend exposure findings", () => {
  const project = { ref: REF, url: `https://${REF}.supabase.co`, serviceKey: null, openTables: [], tablesProbed: 0, schemaListed: false };

  it("reports a service key as critical and each open table as high, with stable check ids", () => {
    const { findings } = summariseResults(results({
      status: "checked",
      projects: [{ ...project, serviceKey: { fingerprint: "eyJhbG…c2lnbm", foundIn: "https://shop.example/app.js" }, openTables: [{ table: "profiles", rowCount: 2 }, { table: "orders", rowCount: 1 }] }],
    }));
    const byId = new Map(findings.map((f) => [f.checkId, f]));
    expect(byId.get(`backend-exposure.service-key:${REF}`)?.severity).toBe("critical");
    expect(byId.get(`backend-exposure.service-key:${REF}`)?.detail).toContain("eyJhbG…c2lnbm");
    expect(byId.get(`backend-exposure.open-table:${REF}:profiles`)).toMatchObject({ severity: "high", title: 'Supabase table "profiles" is readable without signing in' });
    expect(byId.get(`backend-exposure.open-table:${REF}:profiles`)?.detail).toContain("2 rows");
    expect(byId.get(`backend-exposure.open-table:${REF}:orders`)?.detail).toContain("1 row visible");
    expect(byId.get(`backend-exposure.open-table:${REF}:orders`)?.remediation).toContain("enable row level security");
    expect(byId.get(`backend-exposure.service-key:${REF}`)?.complianceRefs?.length).toBeGreaterThan(0);
    expect(byId.get(`backend-exposure.open-table:${REF}:orders`)?.fixDifficulty).toBe("moderate");
  });

  it("reports listable buckets and open Firebase stores with stable check ids", () => {
    const { findings } = summariseResults(results({
      status: "checked",
      projects: [{ ...project, openBuckets: [{ bucket: "avatars" }], bucketsProbed: 1 }],
      firebase: {
        targets: { databases: [], buckets: [], projects: [], collections: [] },
        probed: 3,
        open: [
          { kind: "rtdb", url: "https://shop-default-rtdb.firebaseio.com", keyCount: 1 },
          { kind: "storage", bucket: "shop.appspot.com" },
          { kind: "firestore", project: "shop-app", collection: "orders" },
        ],
      },
    }));
    const byId = new Map(findings.map((f) => [f.checkId, f]));
    expect(byId.get(`backend-exposure.storage-bucket:${REF}:avatars`)).toMatchObject({ severity: "medium", fixDifficulty: "easy" });
    expect(byId.get(`backend-exposure.storage-bucket:${REF}:avatars`)?.remediation).toContain("bucket_id = 'avatars'");
    expect(byId.get("backend-exposure.firebase-rtdb:shop-default-rtdb.firebaseio.com")).toMatchObject({ severity: "high", fixDifficulty: "moderate" });
    expect(byId.get("backend-exposure.firebase-rtdb:shop-default-rtdb.firebaseio.com")?.detail).toContain("1 top-level key.");
    expect(byId.get("backend-exposure.firebase-storage:shop.appspot.com")).toMatchObject({ severity: "medium", fixDifficulty: "easy" });
    expect(byId.get("backend-exposure.firestore:shop-app:orders")).toMatchObject({ severity: "high", title: 'Firestore collection "orders" is readable without signing in' });
    expect(byId.get("backend-exposure.firestore:shop-app:orders")?.remediation).toContain("match /orders/{docId}");
    for (const id of ["firebase-rtdb:shop-default-rtdb.firebaseio.com", "firebase-storage:shop.appspot.com", "firestore:shop-app:orders", `storage-bucket:${REF}:avatars`]) {
      expect(byId.get(`backend-exposure.${id}`)?.complianceRefs?.length).toBeGreaterThan(0);
    }
  });

  it("reports nothing for a project with no evidence, not_applicable or error", () => {
    for (const r of [{ status: "checked" as const, projects: [project] }, { status: "not_applicable" as const }, { status: "error" as const, note: "x" }, undefined]) {
      expect(summariseResults(results(r)).findings.some((f) => f.checkId?.startsWith("backend-exposure."))).toBe(false);
    }
  });

  it("falls back to a safe table name in the remediation SQL", async () => {
    const { backendOpenTableRemediation } = await import("./remediationText");
    expect(backendOpenTableRemediation("odd name; drop")).toContain("public.your_table");
    const { backendStorageBucketRemediation, firestoreOpenRemediation } = await import("./remediationText");
    expect(backendStorageBucketRemediation("x'; drop")).toContain("'your-bucket'");
    expect(firestoreOpenRemediation("a/b")).toContain("match /yourCollection/");
  });
});
