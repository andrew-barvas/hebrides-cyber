// Directory listing (autoindex) scanner — detects Apache/nginx-style raw
// directory browsing left enabled on common upload/asset/backup paths.
// Deliberately scoped to genuine autoindex pages (an "Index of /..."
// title/heading plus a "Parent Directory" link) rather than "probe common
// paths and flag any 200", which would recreate the exact catch-all
// false-positive class exposure.ts was hardened against — see httpProbe.ts.
import {
  type Baseline,
  normaliseBody,
  fetchBaseline,
  matchesBaselineHeaders,
  isCatchAllBody,
} from "./httpProbe";

export type DirectoryListingResult =
  | { status: "checked"; listings: OpenDirectory[] }
  | { status: "error"; note: string };

export type OpenDirectory = {
  path: string;
  // Approximate — derived from anchor count, not a guaranteed exact total.
  fileCount: number | null;
};

const CANDIDATE_PATHS = [
  "/uploads/",
  "/images/",
  "/assets/",
  "/static/",
  "/media/",
  "/files/",
  "/downloads/",
  "/backup/",
  "/backups/",
  "/old/",
  "/tmp/",
  "/temp/",
  "/log/",
  "/logs/",
  "/data/",
  "/db/",
  "/includes/",
  "/wp-content/uploads/",
];

// Apache: <title>Index of /path</title>  —  nginx: <h1>Index of /path</h1>
const INDEX_TITLE = /<(?:title|h1)[^>]*>\s*Index of \/[^<]*<\/(?:title|h1)>/i;
// The link back up a level: Apache labels it "Parent Directory", nginx's
// autoindex links "../" with no such text. Present on virtually every
// autoindex page and almost nowhere else — requiring this and INDEX_TITLE
// together is what makes it safe to flag without a per-path content assertion
// the way exposure.ts needs one for each individual file type.
const PARENT_DIRECTORY = /Parent Directory|<a\s+href=["']\.\.\/["']/i;

function countListedEntries(body: string): number | null {
  const hrefs = body.match(/<a href="(?!\/|\?|\.\.\/?")[^"]+"/gi);
  return hrefs ? hrefs.length : null;
}

async function probeDirectory(baseUrl: string, path: string, baseline: Baseline): Promise<OpenDirectory | null> {
  const url = baseUrl.replace(/\/$/, "") + path;
  try {
    const res = await fetch(url, {
      redirect: "manual", // a redirect elsewhere (e.g. to a 404 page) is not a listing
      signal: AbortSignal.timeout(6000),
    });
    if (res.status !== 200) return null;

    const contentType = res.headers.get("content-type") ?? "";
    if (contentType && !contentType.includes("text/html")) return null;

    if (matchesBaselineHeaders(baseline, res)) return null;

    const text = await res.text().catch(() => "");
    if (!INDEX_TITLE.test(text) || !PARENT_DIRECTORY.test(text)) return null;

    const masked = normaliseBody(text, path);
    if (isCatchAllBody(baseline, masked)) return null;

    return { path, fileCount: countListedEntries(text) };
  } catch {
    return null; // Network errors are not findings.
  }
}

export async function checkDirectoryListing(targetUrl: string): Promise<DirectoryListingResult> {
  try {
    const origin = new URL(targetUrl).origin;
    const baseline = await fetchBaseline(origin);

    const results = await Promise.allSettled(CANDIDATE_PATHS.map((p) => probeDirectory(origin, p, baseline)));

    const listings = results
      .filter((r): r is PromiseFulfilledResult<OpenDirectory> => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    return { status: "checked", listings };
  } catch (err) {
    return { status: "error", note: `Directory listing scan failed: ${(err as Error).message}` };
  }
}
