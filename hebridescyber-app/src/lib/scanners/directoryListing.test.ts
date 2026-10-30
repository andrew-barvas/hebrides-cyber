import { describe, it, expect, vi, afterEach } from "vitest";
import { checkDirectoryListing } from "./directoryListing";

afterEach(() => vi.unstubAllGlobals());

type Reply = { status?: number; body?: string; type?: string; headers?: Record<string, string> };

function serve(routes: Record<string, Reply>, fallback: Reply = { status: 404, body: "Not Found", type: "text/html" }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const r = routes[new URL(url).pathname] ?? fallback;
      return new Response(r.body ?? "", { status: r.status ?? 200, headers: { "content-type": r.type ?? "text/html", ...(r.headers ?? {}) } });
    })
  );
}

const autoindex = (path: string, files: string[]) =>
  `<html><head><title>Index of ${path}</title></head><body><h1>Index of ${path}</h1><pre>` +
  `<a href="../">Parent Directory</a>\n` +
  files.map((f) => `<a href="${f}">${f}</a>`).join("\n") +
  `</pre></body></html>`;

async function listed(url = "https://example.com") {
  const result = await checkDirectoryListing(url);
  if (result.status !== "checked") throw new Error(JSON.stringify(result));
  return result.listings;
}

describe("checkDirectoryListing", () => {
  it("reports a real Apache-style autoindex with an approximate file count", async () => {
    serve({ "/uploads/": { body: autoindex("/uploads/", ["invoice.pdf", "passport.jpg", "db.sql"]) } });
    const [dir] = await listed();
    expect(dir).toMatchObject({ path: "/uploads/", fileCount: 3 });
    // The GET that proved it: status, type, and the "Index of" heading, never the HTML body.
    expect(dir.evidence).toMatchObject({
      request: { method: "GET", url: "https://example.com/uploads/" },
      response: { status: 200, headers: { "content-type": "text/html" } },
      matched: "Index of /uploads/",
    });
    expect(dir.evidence!.response.bodyExcerpt).toBeUndefined();
  });

  // Found by the accuracy benchmark: nginx's autoindex links "../" with no
  // "Parent Directory" text.
  it("reports an nginx-style autoindex", async () => {
    const nginx = `<html><head><title>Index of /assets/</title></head><body><h1>Index of /assets/</h1><hr><pre><a href="../">../</a>\n<a href="app.js">app.js</a>\n<a href="logo.png">logo.png</a>\n</pre><hr></body></html>`;
    serve({ "/assets/": { body: nginx } });
    expect(await listed()).toMatchObject([{ path: "/assets/", fileCount: 2, evidence: { matched: "Index of /assets/" } }]);
  });

  it("still needs the 'Index of' heading when the page only has a ../ link", async () => {
    serve({ "/assets/": { body: `<html><title>Assets</title><a href="../">back</a></html>` } });
    expect(await listed()).toEqual([]);
  });

  it("needs both the 'Index of' heading and a Parent Directory link", async () => {
    serve({
      "/uploads/": { body: "<html><title>Index of /uploads/</title><p>Our uploads</p></html>" },
      "/images/": { body: "<html><a href='../'>Parent Directory</a></html>" },
    });
    expect(await listed()).toEqual([]);
  });

  // An SPA that renders "Index of" text for every route must not be flagged.
  it("ignores a catch-all that serves the same page for every path", async () => {
    serve({}, { status: 200, body: autoindex("/PATH/", ["a"]) });
    expect(await listed()).toEqual([]);
  });

  it("ignores non-HTML and redirected responses", async () => {
    serve({
      "/uploads/": { type: "application/json", body: autoindex("/uploads/", ["a"]) },
      "/images/": { status: 302, headers: { location: "/" } },
    });
    expect(await listed()).toEqual([]);
  });

  it("treats network errors as no findings", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNRESET")));
    expect(await listed()).toEqual([]);
  });

  it("returns an error result for an unparseable target", async () => {
    expect((await checkDirectoryListing("nope")).status).toBe("error");
  });
});
