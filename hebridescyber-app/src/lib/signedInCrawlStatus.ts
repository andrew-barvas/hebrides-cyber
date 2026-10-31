// Whether the signed-in crawl ran, read from a stored scan's results
// (results.extended.authCheck, see authenticatedCheck.ts).
//
// The crawl's failure lives one level down: authCheck reports "checked" for
// its header analysis even when the saved credential was rejected and
// authCheck.crawl is { status: "error" }. Reports that only look at top-level
// statuses therefore showed nothing at all for a rejected login, which reads
// as "signed-in pages clean". This flattens it into one status the report
// page and the executive PDF both use.
//
// Pure, no imports beyond types, so client components can use it.

export type SignedInCrawlStatus =
  | { state: "crawled"; pages: number }
  | { state: "partial"; pages: number; note: string }
  | { state: "failed"; note: string };

type Loose = { status?: unknown; note?: unknown; pages?: unknown; crawl?: unknown } | null | undefined;

const asObject = (v: unknown): Loose => (v && typeof v === "object" ? (v as Loose) : undefined);
const noteOf = (v: Loose, fallback: string) => (typeof v?.note === "string" && v.note ? v.note : fallback);

/**
 * null when the scan didn't attempt a signed-in crawl: no credential
 * connected, the profile left it out, or the scan predates the crawl.
 */
export function signedInCrawlStatus(results: unknown): SignedInCrawlStatus | null {
  const extended = asObject(asObject(results) && (results as { extended?: unknown }).extended);
  const authCheck = asObject(extended && (extended as { authCheck?: unknown }).authCheck);
  if (!authCheck) return null;

  if (authCheck.status === "error") return { state: "failed", note: noteOf(authCheck, "The signed-in check could not complete.") };
  if (authCheck.status !== "checked") return null;

  const crawl = asObject(authCheck.crawl);
  if (!crawl) return null;
  if (crawl.status === "error") return { state: "failed", note: noteOf(crawl, "The signed-in crawl could not complete.") };

  const pages = Array.isArray(crawl.pages) ? crawl.pages.length : 0;
  if (crawl.status === "partial") return { state: "partial", pages, note: noteOf(crawl, "Only part of the site was crawled.") };
  if (crawl.status === "checked") return { state: "crawled", pages };
  return null;
}
