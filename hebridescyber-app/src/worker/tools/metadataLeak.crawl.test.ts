// End-to-end path the `exposure` profile uses for the metadata check: the
// real base crawler reads a real local site, records the documents its pages
// link to, and runMetadataLeakCheck downloads and reads them. No mocks and no
// binary, so this runs in the ordinary unit suite.
//
// It pins down the Lookout promise that the crawl "respects your robots.txt":
// a document under a Disallow path is never recorded, so it is never fetched.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { checkCrawl } from "@/lib/scanners/crawler";
import { runMetadataLeakCheck } from "./metadataLeak";

const PUBLIC_PDF = "%PDF-1.4\n1 0 obj\n<< /Author (Morag Public) /Creator (Microsoft Word) >>\nendobj\n%%EOF";
const PRIVATE_PDF = "%PDF-1.4\n1 0 obj\n<< /Author (Never Fetched) >>\nendobj\n%%EOF";

describe("metadata check over the base crawl", () => {
  let server: Server;
  let base = "";
  const requested: string[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      const path = req.url ?? "/";
      requested.push(path);
      if (path === "/robots.txt") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("User-agent: *\nDisallow: /private/\n");
      } else if (path === "/") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(
          "<html><head><title>Home</title></head><body>" +
            "<a href='/about'>About</a>" +
            "<a href='/docs/annual-report.pdf'>Report</a>" +
            "<a href='/private/board-minutes.pdf'>Minutes</a>" +
            "<a href='https://elsewhere.example/brochure.pdf'>Off-site</a>" +
            "</body></html>"
        );
      } else if (path === "/about") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<html><body><a href='/docs/annual-report.pdf'>Again</a><a href='/docs/missing.pdf'>Broken</a></body></html>");
      } else if (path === "/docs/annual-report.pdf") {
        res.writeHead(200, { "content-type": "application/pdf" });
        res.end(PUBLIC_PDF);
      } else if (path === "/private/board-minutes.pdf") {
        res.writeHead(200, { "content-type": "application/pdf" });
        res.end(PRIVATE_PDF);
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => {
    server.close();
  });

  it("records same-site documents robots.txt allows, once each, and reads their metadata", async () => {
    const crawl = await checkCrawl(`${base}/`);
    if (crawl.status === "error") throw new Error(`crawl failed: ${crawl.note}`);
    expect([...(crawl.documentUrls ?? [])].sort()).toEqual([`${base}/docs/annual-report.pdf`, `${base}/docs/missing.pdf`]);
    // The crawler only records documents; it never downloads them.
    expect(requested).not.toContain("/docs/annual-report.pdf");

    const result = await runMetadataLeakCheck(crawl.documentUrls ?? []);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.findings).toContainEqual({ url: `${base}/docs/annual-report.pdf`, type: "author", value: "Morag Public" });
    expect(result.findings).toContainEqual({ url: `${base}/docs/annual-report.pdf`, type: "software", value: "Microsoft Word" });
    expect(JSON.stringify(result.findings)).not.toContain("Never Fetched");
    expect(requested).not.toContain("/private/board-minutes.pdf");
  });
});
