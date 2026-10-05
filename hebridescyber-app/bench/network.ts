// Informational scan of real, network-dependent targets (badssl.com hosts, a
// local OWASP Juice Shop). There are no must-find expectations here — those
// sites change underneath us — so this prints what the scanner reports and
// never fails on content. Used only by the opt-in job in benchmark.yml.
//   npm run bench:network -- https://expired.badssl.com http://localhost:3000
import { scanTarget } from "./lib/scan";

async function main(): Promise<void> {
  const urls = process.argv.slice(2);
  if (urls.length === 0) {
    console.error("Usage: npm run bench:network -- <url> [<url>...]");
    process.exitCode = 2;
    return;
  }
  for (const url of urls) {
    try {
      const ids = await scanTarget(url);
      console.log(`${url}\n${ids.map((id) => `  ${id}`).join("\n") || "  (no findings)"}`);
    } catch (err) {
      console.log(`${url}\n  scan failed: ${(err as Error).message}`);
    }
  }
}

void main();
