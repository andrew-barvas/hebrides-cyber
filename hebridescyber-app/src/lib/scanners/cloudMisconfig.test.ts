import { describe, it, expect, vi, afterEach } from "vitest";
import { checkCloudMisconfig } from "./cloudMisconfig";

afterEach(() => vi.unstubAllGlobals());

const LIST_S3 = "<ListBucketResult><Name>b</Name><Contents><Key>a.txt</Key></Contents><Contents><Key>b.txt</Key></Contents></ListBucketResult>";
const DENIED = "<Error><Code>AccessDenied</Code></Error>";
const LIST_AZURE = "<EnumerationResults><Blobs><Blob><Name>x</Name></Blob></Blobs></EnumerationResults>";

/** The target page plus whatever the bucket endpoints answer. */
function serve(page: string, buckets: Record<string, { status: number; body: string }>) {
  const fetchMock = vi.fn(async (url: string) => {
    if (url === "https://example.com") return new Response(page, { headers: { "content-type": "text/html" } });
    for (const [prefix, reply] of Object.entries(buckets)) {
      if (url.startsWith(prefix)) return new Response(reply.body, { status: reply.status });
    }
    return new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function publicBuckets() {
  const result = await checkCloudMisconfig("https://example.com");
  if (result.status !== "checked") throw new Error(JSON.stringify(result));
  return result.publicBuckets;
}

describe("checkCloudMisconfig", () => {
  it("reports a referenced S3 bucket that lists publicly, with an object count", async () => {
    serve('<img src="https://acme-assets.s3.amazonaws.com/logo.png">', { "https://acme-assets.s3.amazonaws.com/": { status: 200, body: LIST_S3 } });
    expect(await publicBuckets()).toEqual([
      { provider: "s3", identifier: "acme-assets", url: "https://acme-assets.s3.amazonaws.com/", objectCount: 2 },
    ]);
  });

  it("recognises path-style S3, GCS and Azure Blob references", async () => {
    serve(
      'https://s3.amazonaws.com/path-bucket/a.js https://storage.googleapis.com/gcs-bucket/b.css https://acct.blob.core.windows.net/media/c.png',
      {
        "https://path-bucket.s3.amazonaws.com/": { status: 200, body: LIST_S3 },
        "https://storage.googleapis.com/gcs-bucket": { status: 200, body: LIST_S3 },
        "https://acct.blob.core.windows.net/media?restype=container&comp=list": { status: 200, body: LIST_AZURE },
      }
    );
    const found = await publicBuckets();
    expect(found.map((b) => `${b.provider}:${b.identifier}`).sort()).toEqual(["azure-blob:acct/media", "gcs:gcs-bucket", "s3:path-bucket"]);
  });

  it("does not report a private bucket (403 / AccessDenied)", async () => {
    serve("https://locked.s3.amazonaws.com/x.png", { "https://locked.s3.amazonaws.com/": { status: 403, body: DENIED } });
    expect(await publicBuckets()).toEqual([]);
  });

  it("needs a real listing document, not just a 200", async () => {
    serve("https://cdn-bucket.s3.amazonaws.com/x.png", { "https://cdn-bucket.s3.amazonaws.com/": { status: 200, body: "<html>welcome</html>" } });
    expect(await publicBuckets()).toEqual([]);
  });

  // Out of scope by design: only buckets the customer's own page references.
  it("never probes buckets the page doesn't reference", async () => {
    const fetchMock = serve("<p>no cloud storage here</p>", {});
    expect(await publicBuckets()).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("checks each referenced bucket once, and at most 15", async () => {
    // S3 bucket names are 3–63 characters; the regex rightly enforces that.
    const refs = Array.from({ length: 20 }, (_, i) => `https://bucket-${i}.s3.amazonaws.com/x https://bucket-${i}.s3.amazonaws.com/y`).join(" ");
    const fetchMock = serve(refs, {});
    await publicBuckets();
    expect(fetchMock).toHaveBeenCalledTimes(1 + 15);
  });

  it("returns an error result when the page itself can't be fetched", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ENOTFOUND")));
    expect((await checkCloudMisconfig("https://example.com")).status).toBe("error");
  });
});
