/**
 * Render every Mermaid source (docs/diagrams/*.mmd) to SVG + PNG in
 * docs/diagrams/exports/. The .mmd files are the canonical source of truth;
 * exports/ is derived output committed for slide decks / funder packs / offline use.
 *
 * Usage: npm run docs:diagrams
 *
 * Requires @mermaid-js/mermaid-cli (devDependency). It drives a headless
 * Chromium — the same browser Playwright installs for this repo's e2e/page-health
 * checks — so no extra binary download is needed once `npx playwright install
 * chromium` has run. Cross-platform (no shell globbing); matches the repo's
 * tsx-script convention.
 */
import { readdirSync, mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const diagramsDir = join(here, "..", "..", "docs", "diagrams");
const exportsDir = join(diagramsDir, "exports");

// Puppeteer config so mmdc can find a browser. mermaid-cli bundles Chromium via
// puppeteer, but if that download was skipped (allowScripts policy / offline CI),
// fall back to any system Chrome/Edge. Honours PUPPETEER_EXECUTABLE_PATH first.
const puppeteerConfig = join(exportsDir, ".puppeteer.json");

function findBrowser(): string | undefined {
  const env = process.env.PUPPETEER_EXECUTABLE_PATH;
  if (env && existsSync(env)) return env;
  const candidates = [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  return candidates.find((p) => existsSync(p));
}

function run(): void {
  if (!existsSync(diagramsDir)) {
    console.error(`No diagrams directory at ${diagramsDir}`);
    process.exit(1);
  }
  mkdirSync(exportsDir, { recursive: true });
  const browser = findBrowser();
  const cfg: Record<string, unknown> = {
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  };
  if (browser) {
    cfg.executablePath = browser;
    console.log(`using browser: ${browser}`);
  }
  writeFileSync(puppeteerConfig, JSON.stringify(cfg, null, 2));

  const sources = readdirSync(diagramsDir).filter((f) => f.endsWith(".mmd"));
  if (sources.length === 0) {
    console.error("No .mmd files found.");
    process.exit(1);
  }

  const mmdc = process.platform === "win32" ? "mmdc.cmd" : "mmdc";
  let failed = 0;
  for (const src of sources) {
    const name = basename(src, ".mmd");
    for (const ext of ["svg", "png"] as const) {
      const out = join(exportsDir, `${name}.${ext}`);
      try {
        execFileSync(
          mmdc,
          [
            "--input", join(diagramsDir, src),
            "--output", out,
            "--backgroundColor", "transparent",
            "--puppeteerConfigFile", puppeteerConfig,
            ...(ext === "png" ? ["--scale", "2"] : []),
          ],
          { stdio: "inherit", shell: process.platform === "win32" },
        );
        console.log(`rendered ${name}.${ext}`);
      } catch {
        failed++;
        console.error(`FAILED to render ${name}.${ext}`);
      }
    }
  }
  if (failed > 0) {
    console.error(
      `\n${failed} render(s) failed. If this is a chromium/launch error, run ` +
        `\`npx playwright install chromium\` or set PUPPETEER_EXECUTABLE_PATH, then retry.`,
    );
    process.exit(1);
  }
  console.log(`\nDone: ${sources.length} diagrams -> ${exportsDir}`);
}

run();
