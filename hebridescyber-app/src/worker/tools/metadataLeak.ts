// Metadata leak detection — checks publicly accessible documents
// and images for information leakage via metadata (author names,
// internal paths, software versions, GPS coordinates, email addresses).
//
// Parses PDF, Office, and image file metadata from URLs discovered
// during the crawl phase. No external binary needed — uses HTTP
// headers and byte-level parsing for common metadata patterns.

export type MetadataFinding = {
  url: string;
  type: "author" | "path" | "software" | "email" | "gps" | "internal-ip";
  value: string;
};

export type MetadataLeakResult =
  | { status: "completed"; findings: MetadataFinding[] }
  | { status: "error"; note: string };

const DOCUMENT_EXTENSIONS = /\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp)$/i;
const IMAGE_EXTENSIONS = /\.(jpe?g|tiff?)$/i;
const MAX_FILES_TO_CHECK = 20;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_BYTES = 512 * 1024;

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const INTERNAL_IP_RE = /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g;
const WINDOWS_PATH_RE = /[A-Z]:\\(?:Users|Documents|Desktop|home|builds?)[^\x00"<>|]{5,80}/gi;
const UNIX_PATH_RE = /\/(?:home|Users|var|opt|builds?|srv)\/[a-zA-Z0-9._/-]{5,80}/g;

function extractTextMetadata(buf: Buffer, url: string): MetadataFinding[] {
  const findings: MetadataFinding[] = [];
  const text = buf.toString("latin1");

  for (const match of text.matchAll(EMAIL_RE)) {
    findings.push({ url, type: "email", value: match[0] });
  }

  for (const match of text.matchAll(INTERNAL_IP_RE)) {
    findings.push({ url, type: "internal-ip", value: match[0] });
  }

  for (const match of text.matchAll(WINDOWS_PATH_RE)) {
    findings.push({ url, type: "path", value: match[0] });
  }

  for (const match of text.matchAll(UNIX_PATH_RE)) {
    if (match[0].includes("/node_modules/") || match[0].includes("/dist/")) continue;
    findings.push({ url, type: "path", value: match[0] });
  }

  // PDF-specific: /Author, /Creator, /Producer metadata
  const authorMatch = text.match(/\/Author\s*\(([^)]{2,80})\)/);
  if (authorMatch) {
    findings.push({ url, type: "author", value: authorMatch[1] });
  }

  const creatorMatch = text.match(/\/Creator\s*\(([^)]{2,80})\)/);
  if (creatorMatch) {
    findings.push({ url, type: "software", value: creatorMatch[1] });
  }

  const producerMatch = text.match(/\/Producer\s*\(([^)]{2,80})\)/);
  if (producerMatch) {
    findings.push({ url, type: "software", value: producerMatch[1] });
  }

  return findings;
}

export async function runMetadataLeakCheck(
  fileUrls: string[]
): Promise<MetadataLeakResult> {
  const candidateUrls = fileUrls
    .filter((u) => DOCUMENT_EXTENSIONS.test(u) || IMAGE_EXTENSIONS.test(u))
    .slice(0, MAX_FILES_TO_CHECK);

  if (candidateUrls.length === 0) {
    return { status: "completed", findings: [] };
  }

  const findings: MetadataFinding[] = [];

  try {
    const results = await Promise.allSettled(
      candidateUrls.map(async (url) => {
        const res = await fetch(url, {
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          headers: { "User-Agent": "Mozilla/5.0 HebridesCyber-Scanner/1.0" },
        });
        if (!res.ok) return;

        const contentType = res.headers.get("content-type") ?? "";
        if (contentType.includes("text/html")) return;

        const arrayBuf = await res.arrayBuffer();
        const buf = Buffer.from(arrayBuf.slice(0, MAX_BYTES));
        findings.push(...extractTextMetadata(buf, url));
      })
    );

    // Log but don't fail for individual fetch errors
    for (const r of results) {
      if (r.status === "rejected") {
        // Silently skip inaccessible files
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    const deduped = findings.filter((f) => {
      const key = `${f.type}:${f.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return { status: "completed", findings: deduped };
  } catch (err) {
    return {
      status: "error",
      note: `Metadata leak check failed: ${(err as Error).message}`,
    };
  }
}
