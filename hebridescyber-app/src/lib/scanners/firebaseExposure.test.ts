import { describe, it, expect, vi, afterEach } from "vitest";
import {
  discoverFirebase,
  firestoreHasDocuments,
  hasFirebase,
  probeFirebase,
  rtdbKeyCount,
  storageListHasEntries,
  type FirebaseTargets,
} from "./firebaseExposure";

afterEach(() => {
  vi.unstubAllGlobals();
});

// A Firebase web config the way bundlers emit it (minified) and the way people paste it (JSON-ish).
const MINIFIED = `const c={apiKey:"AIzaSyX",authDomain:"shop-app.firebaseapp.com",databaseURL:"https://shop-app-default-rtdb.firebaseio.com",projectId:"shop-app",storageBucket:"shop-app.appspot.com"};`;
const PASTED = `{ "databaseURL": "https://eu-shop-default-rtdb.europe-west1.firebasedatabase.app/", "storageBucket": 'eu-shop.firebasestorage.app', "projectId": "eu-shop" }`;

describe("discoverFirebase", () => {
  it("reads databases, buckets and projects from the site's own config, and collections from its code", () => {
    const t = discoverFirebase([
      { label: "page", text: MINIFIED },
      { label: "app.js", text: `${PASTED}; db.collection("orders"); collection(db, 'users'); getDocs(collection(firestore, \`posts\`))` },
    ]);
    expect(t).toEqual({
      databases: ["https://shop-app-default-rtdb.firebaseio.com", "https://eu-shop-default-rtdb.europe-west1.firebasedatabase.app"],
      buckets: ["shop-app.appspot.com", "eu-shop.firebasestorage.app"],
      projects: ["shop-app", "eu-shop"],
      collections: ["orders", "users", "posts"],
    });
    expect(hasFirebase(t)).toBe(true);
  });

  it("ignores a firebaseio.com URL that isn't the site's databaseURL (a public API the site merely reads)", () => {
    const t = discoverFirebase([{ label: "p", text: `fetch("https://hacker-news.firebaseio.com/v0/topstories.json")` }]);
    expect(t.databases).toEqual([]);
    expect(hasFirebase(t)).toBe(false);
  });

  it("ignores values that could steer a request off Google's domains", () => {
    const t = discoverFirebase([
      {
        label: "p",
        text: `databaseURL:"https://evil.example.com" databaseURL:"https://x.firebaseio.com.evil.example" storageBucket:"bucket.evil.example" projectId:"A_bad id" collection(db, "../admin")`,
      },
    ]);
    expect(t).toEqual({ databases: [], buckets: [], projects: [], collections: [] });
  });

  it("caps each kind", () => {
    const text = Array.from({ length: 6 }, (_, i) => `databaseURL:"https://db${i}x.firebaseio.com" storageBucket:"b${i}xx.appspot.com" projectId:"proj${i}x"`).join(" ")
      + Array.from({ length: 15 }, (_, i) => ` db.collection("c${i}")`).join("");
    const t = discoverFirebase([{ label: "p", text }]);
    expect(t.databases).toHaveLength(3);
    expect(t.buckets).toHaveLength(3);
    expect(t.projects).toHaveLength(3);
    expect(t.collections).toHaveLength(10);
  });
});

describe("evidence helpers", () => {
  it("counts RTDB keys only from a 200 with a non-empty object", () => {
    expect(rtdbKeyCount({ status: 200, json: { users: true, orders: true } })).toBe(2);
    expect(rtdbKeyCount({ status: 200, json: null })).toBeNull(); // open but empty: proves nothing
    expect(rtdbKeyCount({ status: 200, json: {} })).toBeNull();
    expect(rtdbKeyCount({ status: 200, json: ["a"] })).toBeNull();
    expect(rtdbKeyCount({ status: 200, json: "text" })).toBeNull();
    expect(rtdbKeyCount({ status: 401, json: { error: "Permission denied" } })).toBeNull();
    expect(rtdbKeyCount(null)).toBeNull();
  });

  it("sees a Storage listing only when it names an object or folder", () => {
    expect(storageListHasEntries({ status: 200, json: { items: [{ name: "a.png" }] } })).toBe(true);
    expect(storageListHasEntries({ status: 200, json: { prefixes: ["uploads/"], items: [] } })).toBe(true);
    expect(storageListHasEntries({ status: 200, json: { prefixes: [], items: [] } })).toBe(false);
    expect(storageListHasEntries({ status: 200, json: undefined })).toBe(false);
    expect(storageListHasEntries({ status: 403, json: { error: { code: 403 } } })).toBe(false);
    expect(storageListHasEntries(null)).toBe(false);
  });

  it("sees Firestore documents only in a 200 with a non-empty documents list", () => {
    expect(firestoreHasDocuments({ status: 200, json: { documents: [{ name: "projects/p/databases/(default)/documents/users/1" }] } })).toBe(true);
    expect(firestoreHasDocuments({ status: 200, json: {} })).toBe(false); // empty collection
    expect(firestoreHasDocuments({ status: 200, json: { documents: "x" } })).toBe(false);
    expect(firestoreHasDocuments({ status: 200, json: null })).toBe(false);
    expect(firestoreHasDocuments({ status: 403, json: { error: { status: "PERMISSION_DENIED" } } })).toBe(false);
    expect(firestoreHasDocuments(null)).toBe(false);
  });
});

type Route = { status?: number; body?: string } | (() => never);

function stub(routes: Record<string, Route>) {
  const calls: { url: string; method: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: init?.method ?? "GET" });
      const route = routes[url];
      if (typeof route === "function") return route();
      if (!route) return new Response('{"error":"Permission denied"}', { status: 401 });
      return new Response(route.body ?? "", { status: route.status ?? 200 });
    })
  );
  return calls;
}

const DB = "https://shop-app-default-rtdb.firebaseio.com";
const BUCKET = "shop-app.appspot.com";
const STORAGE_URL = `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o?maxResults=1`;
const firestoreUrl = (project: string, c: string) => `https://firestore.googleapis.com/v1/projects/${project}/databases/(default)/documents/${c}?pageSize=1&mask.fieldPaths=__name__`;

describe("probeFirebase", () => {
  const targets: FirebaseTargets = { databases: [DB], buckets: [BUCKET], projects: ["shop-app", "other-app"], collections: ["users", "posts", "empty"] };

  it("reports only stores that returned something readable, with GETs to Google's hosts only", async () => {
    const calls = stub({
      [`${DB}/.json?shallow=true`]: { body: JSON.stringify({ users: true, orders: true, config: true }) },
      [STORAGE_URL]: { body: JSON.stringify({ prefixes: [], items: [{ name: "invoices/1.pdf", bucket: BUCKET }] }) },
      [firestoreUrl("shop-app", "users")]: { body: JSON.stringify({ documents: [{ name: "x" }] }) },
      [firestoreUrl("shop-app", "posts")]: { status: 403, body: JSON.stringify({ error: { status: "PERMISSION_DENIED" } }) },
      [firestoreUrl("shop-app", "empty")]: { body: "{}" },
    });
    const result = await probeFirebase(targets);
    expect(result.open).toEqual([
      { kind: "rtdb", url: DB, keyCount: 3 },
      { kind: "storage", bucket: BUCKET },
      { kind: "firestore", project: "shop-app", collection: "users" },
    ]);
    // Only the first project's Firestore is asked about.
    expect(result.probed).toBe(5);
    expect(calls.some((c) => c.url.includes("other-app"))).toBe(false);
    expect(calls.every((c) => c.method === "GET")).toBe(true);
    for (const c of calls) {
      expect(["shop-app-default-rtdb.firebaseio.com", "firebasestorage.googleapis.com", "firestore.googleapis.com"]).toContain(new URL(c.url).hostname);
    }
  });

  it("reports nothing for locked stores, unreadable bodies or network failures", async () => {
    const boom = (): never => {
      throw new Error("network down");
    };
    stub({
      [`${DB}/.json?shallow=true`]: boom,
      [STORAGE_URL]: { body: "<html>not json</html>" },
    });
    const result = await probeFirebase(targets);
    expect(result.open).toEqual([]);
    expect(result.probed).toBe(5);
  });

  it("asks Firestore nothing without a project", async () => {
    const calls = stub({});
    const result = await probeFirebase({ databases: [], buckets: [], projects: [], collections: ["users"] });
    expect(result).toEqual({ targets: { databases: [], buckets: [], projects: [], collections: ["users"] }, open: [], probed: 0 });
    expect(calls).toHaveLength(0);
  });
});
