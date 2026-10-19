// Runs the base scanner modules that can be exercised against a local HTTP
// fixture (no DNS, no third-party lookups) and derives findings through the
// real summariseResults() — so what's measured is exactly what customers see.
import { checkTls } from "@/lib/scanners/tls";
import { checkHeaders } from "@/lib/scanners/headers";
import { checkExposure } from "@/lib/scanners/exposure";
import { checkDirectoryListing } from "@/lib/scanners/directoryListing";
import { checkFingerprint, getCmsType } from "@/lib/scanners/fingerprint";
import { checkWebApp } from "@/lib/scanners/webapp";
import { checkBusinessLogic } from "@/lib/scanners/businessLogic";
import { checkGraphql } from "@/lib/scanners/graphql";
import { checkCrawl } from "@/lib/scanners/crawler";
import { summariseResults, type ScanResults } from "@/lib/scanners";
import { setRetireRepositoryForTests, type RetireRepository } from "@/lib/scanners/retireJs";
import retireSubset from "../fixtures/retire-subset.json";

// The real retire.js entries (jquery, jquery-ui, lodash) copied unchanged from
// the pinned commit (RETIRE_DATA_COMMIT), so the default run stays offline and
// measures the real extractors and ranges. Apache-2.0: docs/THIRD-PARTY-NOTICES.md.
setRetireRepositoryForTests(retireSubset as RetireRepository);

/** Modules the benchmark can drive offline. Anything else is out of scope. */
export const BENCH_MODULES = [
  "tls",
  "headers",
  "exposure",
  "directory-listing",
  "fingerprint",
  "webapp",
  "business-logic",
  "graphql",
  "crawl",
  "malware",
] as const;

export type BenchModule = (typeof BENCH_MODULES)[number];

const NOT_RUN = { status: "error", note: "not run by the benchmark" };

/** Returns the checkIds the scanner reports for `targetUrl`. */
export async function scanTarget(targetUrl: string): Promise<string[]> {
  const [tls, headers, exposure, directoryListing, fingerprint, businessLogic, graphql, crawl] = await Promise.all([
    checkTls(targetUrl),
    checkHeaders(targetUrl),
    checkExposure(targetUrl),
    checkDirectoryListing(targetUrl),
    checkFingerprint(targetUrl),
    checkBusinessLogic(targetUrl),
    checkGraphql(targetUrl),
    // The real crawler walks the fixture (loopback, no internet): its per-page
    // results drive buildCrawlFindings (crawl.*) and buildMalwareFindings
    // (malware.*) in summariseResults, so injected-content detection is scored.
    checkCrawl(targetUrl),
  ]);
  const cmsType = getCmsType(fingerprint.status === "checked" ? fingerprint.technologies : []);
  const webapp = await checkWebApp(targetUrl, {
    isWordPress: cmsType === "wordpress",
    isJoomla: cmsType === "joomla",
    isDrupal: cmsType === "drupal",
    isMagento: cmsType === "magento",
    isShopify: cmsType === "shopify",
  });

  // Every module the benchmark does not drive reports "error", which
  // summariseResults() skips — so only the modules above can produce findings.
  const results = {
    target_url: targetUrl,
    checked_at: new Date().toISOString(),
    tls,
    headers,
    dns: NOT_RUN,
    exposure,
    directoryListing,
    cloudMisconfig: NOT_RUN,
    fingerprint,
    ports: NOT_RUN,
    playwright: NOT_RUN,
    recon: NOT_RUN,
    webapp,
    safeBrowsing: NOT_RUN,
    waybackDiscovery: NOT_RUN,
    hibp: NOT_RUN,
    wpVulnDb: NOT_RUN,
    softwareCveDb: NOT_RUN,
    businessLogic,
    apiSpec: NOT_RUN,
    graphql,
    crawl,
    zap: NOT_RUN,
  } as unknown as ScanResults;

  const { findings } = summariseResults(results);
  return findings
    .map((f) => f.checkId)
    .filter((id): id is string => typeof id === "string" && id !== "meta.no-issues");
}
