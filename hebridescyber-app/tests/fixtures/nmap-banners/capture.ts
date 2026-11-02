// Re-records src/worker/tools/fixtures/nmap/banner-services.xml: starts every
// banner listener on loopback, runs the real nmap exactly as
// networkExposure.ts does (-sV --open -p <ports> -oX -), and writes its XML.
//
//   npx tsx tests/fixtures/nmap-banners/capture.ts [out-file]
//
// Needs nmap on PATH. Loopback only: nothing leaves the machine.
import { writeFileSync } from "node:fs";
import { execTool } from "../../../src/lib/execTool";
import { ALL_BANNERS, startBannerListener } from "./bannerServices";

async function main() {
  const out = process.argv[2] ?? "src/worker/tools/fixtures/nmap/banner-services.xml";
  const listeners = await Promise.all(ALL_BANNERS.map((kind) => startBannerListener(kind)));
  try {
    const ports = listeners.map((l) => l.port).join(",");
    const { stdout } = await execTool("nmap", ["-sV", "--open", "-p", ports, "-oX", "-", "127.0.0.1"], { timeout: 180_000 });
    writeFileSync(out, stdout);
    for (const l of listeners) console.log(`${l.kind} on ${l.port}`);
    console.log(`Wrote ${out}`);
  } finally {
    await Promise.all(listeners.map((l) => l.close()));
  }
}

main().catch((err) => {
  console.error("capture failed:", (err as Error).message);
  process.exit(1);
});
