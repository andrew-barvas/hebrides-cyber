// Shared false-positive-hardening machinery for scanners that probe a list of
// paths against a target and need to tell "this path is genuinely different"
// from "this server 200s a catch-all shell for everything" — originally built
// for exposure.ts, extracted here so directoryListing.ts (and any future
// path-probing check) reuses the exact same, already-proven logic rather than
// risking a second copy that drifts out of sync.

/**
 * Baseline response fingerprint for the site root plus a known-nonexistent
 * path. Used to detect catch-all patterns where every URL returns the same
 * shell — the single biggest source of false positives in path-probing
 * checks (see exposure.ts's git history for the false-positive class this
 * was built to close).
 */
export type Baseline = {
  etag: string | null;
  contentLength: string | null;
  // Body of a URL that definitely does not exist. If a probe response matches
  // this, the server is serving a catch-all and the "finding" is a phantom.
  notFoundBody: string | null;
  // True when the catch-all probe returned HTTP 200 for a random path — the
  // server never 404s, so status alone carries no information.
  servesCatchAll: boolean;
};

/**
 * Collapse whitespace, strip the requested path, and cap length, so two
 * renders of the same shell compare equal.
 *
 * Stripping the path matters: SPA shells routinely echo the requested URL back
 * into the markup (router state, a canonical link, an error message). That
 * makes every probe's body differ from the baseline's, and can also make a
 * probe's raw path text satisfy a content check that was meant to detect
 * something else entirely. Masking the path removes both problems at once.
 */
export function normaliseBody(body: string, requestPath: string): string {
  let out = body.replace(/\s+/g, " ").trim();
  for (const variant of [requestPath, encodeURIComponent(requestPath), requestPath.replace(/^\//, "")]) {
    if (variant.length < 3) continue;
    out = out.split(variant).join(" PATH ");
  }
  return out.slice(0, 4000);
}

/** Length of the longest shared prefix of two strings. */
function commonPrefixLen(a: string, b: string): number {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[i] === b[i]) i++;
  return i;
}

/** Length of the longest shared suffix of two strings. */
function commonSuffixLen(a: string, b: string): number {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}

/**
 * True when two response bodies are almost certainly the same document.
 *
 * After path masking most catch-all shells compare byte-identical. The
 * prefix/suffix test covers what's left: a nonce, build hash, or CSRF token
 * embedded mid-document, which leaves a small variable region between two
 * large identical stretches.
 */
export function looksLikeSameDocument(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (a === b) return true;

  const shorter = Math.min(a.length, b.length);
  if (shorter < 80) return false; // too little signal to judge

  const shared = commonPrefixLen(a, b) + commonSuffixLen(a, b);
  return shared >= shorter * 0.85;
}

/**
 * Fingerprints the site root AND a URL that cannot exist. The second request is
 * what stops a check reporting "/.env exposed" (or "/uploads/ is browsable")
 * on every SPA on the internet: if a random path returns 200 with the app
 * shell, then so will the real probe paths, and the only way to tell a real
 * finding from the shell is to compare the bodies.
 */
export async function fetchBaseline(origin: string): Promise<Baseline> {
  const randomSlug = `/hc-probe-${crypto.randomUUID()}`;

  const [rootRes, notFoundRes] = await Promise.allSettled([
    fetch(origin + "/", {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    }),
    fetch(origin + randomSlug, {
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    }),
  ]);

  const etag = rootRes.status === "fulfilled" ? rootRes.value.headers.get("etag") : null;
  const contentLength = rootRes.status === "fulfilled" ? rootRes.value.headers.get("content-length") : null;

  let notFoundBody: string | null = null;
  let servesCatchAll = false;
  if (notFoundRes.status === "fulfilled") {
    servesCatchAll = notFoundRes.value.status === 200;
    if (servesCatchAll) {
      notFoundBody = await notFoundRes.value
        .text()
        .then((t) => normaliseBody(t, randomSlug))
        .catch(() => null);
    }
  }

  return { etag, contentLength, notFoundBody, servesCatchAll };
}

/**
 * True if this probe response's ETag/Content-Length matches the site root's —
 * belt-and-suspenders signal that the server is returning the homepage for
 * every path, on top of the body comparison in isCatchAllBody.
 */
export function matchesBaselineHeaders(baseline: Baseline, res: Response): boolean {
  const resEtag = res.headers.get("etag");
  if (baseline.etag && resEtag && resEtag === baseline.etag) return true;
  if (!baseline.etag && baseline.contentLength) {
    const resLen = res.headers.get("content-length");
    if (resLen && resLen === baseline.contentLength) return true;
  }
  return false;
}

/** True if this (already path-masked) body matches the known-404 baseline body. */
export function isCatchAllBody(baseline: Baseline, maskedBody: string): boolean {
  return Boolean(baseline.notFoundBody) && looksLikeSameDocument(maskedBody, baseline.notFoundBody!);
}
