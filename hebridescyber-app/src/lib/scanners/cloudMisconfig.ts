// Cloud storage misconfiguration scanner — finds S3/Azure Blob/GCS bucket
// references in the target's own page source, then tests only THOSE buckets
// for public listing. Deliberately never enumerates candidate bucket names —
// that would mean scanning third-party infrastructure the customer doesn't
// own, which is out of scope for an authorised scan of a single target.
export type CloudMisconfigResult =
  | { status: "checked"; publicBuckets: PublicBucket[] }
  | { status: "error"; note: string };

export type PublicBucket = {
  provider: "s3" | "azure-blob" | "gcs";
  identifier: string; // bucket name, or "account/container" for azure-blob
  url: string;
  // Approximate — from counting listed entries in the XML response.
  objectCount: number | null;
};

type Candidate = { provider: PublicBucket["provider"]; identifier: string };

const BUCKET_PATTERNS: {
  provider: PublicBucket["provider"];
  re: RegExp;
  extract: (m: RegExpMatchArray) => string | null;
}[] = [
  // Virtual-hosted-style: https://{bucket}.s3.amazonaws.com or https://{bucket}.s3-us-west-2.amazonaws.com
  {
    provider: "s3",
    re: /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-][a-z0-9-]*\.?amazonaws\.com/gi,
    extract: (m) => m[1]?.toLowerCase() ?? null,
  },
  // Path-style: https://s3.amazonaws.com/{bucket} or https://s3-us-west-2.amazonaws.com/{bucket}
  {
    provider: "s3",
    re: /https?:\/\/s3[.-][a-z0-9-]*\.?amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
    extract: (m) => m[1]?.toLowerCase() ?? null,
  },
  // Azure Blob container: https://{account}.blob.core.windows.net/{container}
  {
    provider: "azure-blob",
    re: /https?:\/\/([a-z0-9]+)\.blob\.core\.windows\.net\/([a-z0-9-]+)/gi,
    extract: (m) => (m[1] && m[2] ? `${m[1]}/${m[2]}` : null),
  },
  // GCS: https://storage.googleapis.com/{bucket}
  {
    provider: "gcs",
    re: /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi,
    extract: (m) => m[1]?.toLowerCase() ?? null,
  },
];

// A page referencing more distinct buckets than this is unusual — the cap
// bounds worst-case request volume against third-party infrastructure.
const MAX_CANDIDATES = 15;

function extractCandidates(html: string): Candidate[] {
  const seen = new Set<string>();
  const candidates: Candidate[] = [];
  for (const { provider, re, extract } of BUCKET_PATTERNS) {
    for (const m of html.matchAll(re)) {
      const identifier = extract(m);
      if (!identifier) continue;
      const key = `${provider}:${identifier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ provider, identifier });
    }
  }
  return candidates;
}

function countXmlEntries(body: string, tag: string): number | null {
  const matches = body.match(new RegExp(`<${tag}>`, "gi"));
  return matches ? matches.length : null;
}

async function checkS3Bucket(bucket: string): Promise<PublicBucket | null> {
  const url = `https://${bucket}.s3.amazonaws.com/`;
  try {
    const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(8_000) });
    if (res.status !== 200) return null;
    const body = await res.text().catch(() => "");
    if (!/<ListBucketResult/i.test(body)) return null;
    return { provider: "s3", identifier: bucket, url, objectCount: countXmlEntries(body, "Key") };
  } catch {
    return null;
  }
}

async function checkGcsBucket(bucket: string): Promise<PublicBucket | null> {
  const url = `https://storage.googleapis.com/${bucket}`;
  try {
    // GCS's XML API mirrors S3's — same response shape, same detection logic.
    const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(8_000) });
    if (res.status !== 200) return null;
    const body = await res.text().catch(() => "");
    if (!/<ListBucketResult/i.test(body)) return null;
    return { provider: "gcs", identifier: bucket, url, objectCount: countXmlEntries(body, "Key") };
  } catch {
    return null;
  }
}

async function checkAzureContainer(accountContainer: string): Promise<PublicBucket | null> {
  const [account, container] = accountContainer.split("/");
  const listUrl = `https://${account}.blob.core.windows.net/${container}?restype=container&comp=list`;
  try {
    const res = await fetch(listUrl, { redirect: "follow", signal: AbortSignal.timeout(8_000) });
    if (res.status !== 200) return null;
    const body = await res.text().catch(() => "");
    if (!/<EnumerationResults/i.test(body)) return null;
    return {
      provider: "azure-blob",
      identifier: accountContainer,
      url: `https://${account}.blob.core.windows.net/${container}`,
      objectCount: countXmlEntries(body, "Blob"),
    };
  } catch {
    return null;
  }
}

function checkCandidate(c: Candidate): Promise<PublicBucket | null> {
  if (c.provider === "s3") return checkS3Bucket(c.identifier);
  if (c.provider === "gcs") return checkGcsBucket(c.identifier);
  return checkAzureContainer(c.identifier);
}

export async function checkCloudMisconfig(targetUrl: string): Promise<CloudMisconfigResult> {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(10_000) });
    const html = await res.text().catch(() => "");

    const candidates = extractCandidates(html).slice(0, MAX_CANDIDATES);
    const results = await Promise.allSettled(candidates.map(checkCandidate));

    const publicBuckets = results
      .filter((r): r is PromiseFulfilledResult<PublicBucket> => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    return { status: "checked", publicBuckets };
  } catch (err) {
    return { status: "error", note: `Cloud misconfiguration scan failed: ${(err as Error).message}` };
  }
}
