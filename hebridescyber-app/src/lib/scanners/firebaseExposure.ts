// Firebase exposure: the Firebase counterpart of backendExposure.ts's Supabase
// check, run from the same material (the page's HTML and same-origin scripts).
//
// A Firebase web config (apiKey, databaseURL, storageBucket, projectId) is
// public by design; what protects the data is the project's security rules.
// This asks, with plain GETs and nothing from the visitor's account, whether
// the rules let a stranger read:
//   - the Realtime Database:  GET <db>/.json?shallow=true  (top-level key
//     names only, never values);
//   - Cloud Storage:          GET .../v0/b/<bucket>/o?maxResults=1 (object names);
//   - Firestore collections the page's own code names:
//     GET .../documents/<collection>?pageSize=1&mask.fieldPaths=__name__
//     (document names only).
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md): a store is reported only
// when the answer proves something readable (a 200 with at least one key,
// object or document). Locked stores answer 401/403 ("Permission denied"); an
// empty store or any other failure proves nothing and is never reported. No
// field value is requested or kept. Only hosts built from names found on the
// page, on Google's Firebase domains, are ever contacted.
//
// Databases and buckets come only from the site's own Firebase config keys
// (`databaseURL`, `storageBucket`, `projectId`), never from any firebaseio.com
// URL on the page: a site that reads a deliberately public database (the
// Hacker News API is one) must not be told its own database is open.

export type FirebaseSource = { label: string; text: string };

export type FirebaseTargets = {
  /** Realtime Database base URLs, e.g. https://my-app-default-rtdb.firebaseio.com */
  databases: string[];
  /** Storage bucket names, e.g. my-app.appspot.com */
  buckets: string[];
  /** Firebase project ids (for Firestore). */
  projects: string[];
  /** Collection names the page's code reads. */
  collections: string[];
};

export type FirebaseFinding =
  | { kind: "rtdb"; url: string; keyCount: number }
  | { kind: "storage"; bucket: string }
  | { kind: "firestore"; project: string; collection: string };

export type FirebaseExposure = {
  /** What was found on the page, so the report can say what was asked about. */
  targets: FirebaseTargets;
  open: FirebaseFinding[];
  probed: number;
};

const PROBE_TIMEOUT_MS = 8_000;
const MAX_BODY_CHARS = 200_000;
const MAX_PER_KIND = 3;
const MAX_COLLECTIONS = 10;

// Names are DNS-label-like; anything else is ignored, so a hostile page cannot steer a request elsewhere.
const DATABASE_URL_RE = /databaseURL["']?\s*[:=]\s*["']https:\/\/([a-z0-9][a-z0-9-]{1,62})\.(firebaseio\.com|[a-z0-9-]{2,30}\.firebasedatabase\.app)\/?["']/g;
const BUCKET_RE = /storageBucket["']?\s*[:=]\s*["']([a-z0-9][a-z0-9._-]{2,62}\.(?:appspot\.com|firebasestorage\.app))["']/g;
const PROJECT_RE = /projectId["']?\s*[:=]\s*["']([a-z][a-z0-9-]{4,28}[a-z0-9])["']/g;
const COLLECTION_RE = /\bcollection\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?["'`]([A-Za-z][A-Za-z0-9_-]{0,63})["'`]\s*\)/g;

/** Pure: Firebase endpoints and collection names found in page text. */
export function discoverFirebase(sources: FirebaseSource[]): FirebaseTargets {
  const databases = new Set<string>();
  const buckets = new Set<string>();
  const projects = new Set<string>();
  const collections = new Set<string>();
  for (const { text } of sources) {
    for (const m of text.matchAll(DATABASE_URL_RE)) databases.add(`https://${m[1]}.${m[2]}`);
    for (const m of text.matchAll(BUCKET_RE)) buckets.add(m[1]);
    for (const m of text.matchAll(PROJECT_RE)) projects.add(m[1]);
    for (const m of text.matchAll(COLLECTION_RE)) collections.add(m[1]);
  }
  return {
    databases: [...databases].slice(0, MAX_PER_KIND),
    buckets: [...buckets].slice(0, MAX_PER_KIND),
    projects: [...projects].slice(0, MAX_PER_KIND),
    collections: [...collections].slice(0, MAX_COLLECTIONS),
  };
}

export function hasFirebase(t: FirebaseTargets): boolean {
  return t.databases.length + t.buckets.length + t.projects.length > 0;
}

type Reply = { status: number; json: unknown } | null;

async function getJson(url: string): Promise<Reply> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS), headers: { accept: "application/json" } });
    const text = (await res.text()).slice(0, MAX_BODY_CHARS);
    try {
      return { status: res.status, json: JSON.parse(text) as unknown };
    } catch {
      return { status: res.status, json: undefined };
    }
  } catch {
    return null;
  }
}

/** Top-level key count from a shallow RTDB read; null when nothing readable came back (null, error, locked). */
export function rtdbKeyCount(reply: Reply): number | null {
  if (!reply || reply.status !== 200) return null;
  const json = reply.json;
  if (!json || typeof json !== "object" || Array.isArray(json)) return null;
  const keys = Object.keys(json as object).length;
  return keys > 0 ? keys : null;
}

/** True when a Cloud Storage list answer contains at least one object or folder. */
export function storageListHasEntries(reply: Reply): boolean {
  if (!reply || reply.status !== 200 || !reply.json || typeof reply.json !== "object") return false;
  const body = reply.json as { items?: unknown; prefixes?: unknown };
  return (Array.isArray(body.items) && body.items.length > 0) || (Array.isArray(body.prefixes) && body.prefixes.length > 0);
}

/** True when a Firestore list answer contains at least one document. */
export function firestoreHasDocuments(reply: Reply): boolean {
  if (!reply || reply.status !== 200 || !reply.json || typeof reply.json !== "object") return false;
  const docs = (reply.json as { documents?: unknown }).documents;
  return Array.isArray(docs) && docs.length > 0;
}

/** Every probe for the targets, in a fixed order, run in parallel (each is one GET to Google). */
export async function probeFirebase(targets: FirebaseTargets): Promise<FirebaseExposure> {
  const probes: Promise<FirebaseFinding | null>[] = [];
  for (const url of targets.databases) {
    probes.push(getJson(`${url}/.json?shallow=true`).then((r) => {
      const keyCount = rtdbKeyCount(r);
      return keyCount === null ? null : { kind: "rtdb", url, keyCount };
    }));
  }
  for (const bucket of targets.buckets) {
    probes.push(getJson(`https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}/o?maxResults=1`).then((r) => (storageListHasEntries(r) ? { kind: "storage", bucket } : null)));
  }
  // One config per site is the norm; only the first project's Firestore is asked about.
  const project = targets.projects[0];
  if (project) {
    for (const collection of targets.collections) {
      const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(project)}/databases/(default)/documents/${encodeURIComponent(collection)}?pageSize=1&mask.fieldPaths=__name__`;
      probes.push(getJson(url).then((r) => (firestoreHasDocuments(r) ? { kind: "firestore", project, collection } : null)));
    }
  }
  const settled = await Promise.all(probes);
  return { targets, open: settled.filter((f): f is FirebaseFinding => f !== null), probed: probes.length };
}
