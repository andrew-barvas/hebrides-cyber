import { describe, it, expect } from "vitest";
import { collectTechInventory } from "./techInventory";
import type { FingerprintResult } from "./fingerprint";
import type { WebAppResult } from "./webapp";

const fp = (...technologies: Array<Record<string, unknown>>) =>
  ({ status: "checked", technologies, riskySoftware: [] }) as unknown as FingerprintResult;

describe("collectTechInventory", () => {
  it("lists every detected technology, versioned or not, with the distribution hint", () => {
    const out = collectTechInventory(
      fp({ name: "PHP", version: "7.4.3", packagedBy: "Ubuntu" }, { name: "WordPress", version: null }),
      null
    );
    expect(out).toEqual([
      { tech: "PHP", version: "7.4.3", packagedBy: "Ubuntu", source: "fingerprint", reportedVulnerable: false },
      { tech: "WordPress", version: null, packagedBy: null, source: "fingerprint", reportedVulnerable: false },
    ]);
  });

  it("lets webapp's more precise versions win, keeping order, and flags libraries it reported", () => {
    const webapp = {
      status: "checked",
      drupal: { version: "9.5.11" },
      joomla: { version: null },
      jsLibraries: [
        { name: "jQuery", version: "1.12.4", isVulnerable: true, reason: "" },
        { name: "Moment.js", version: "unknown", isVulnerable: false, reason: "" },
      ],
    } as unknown as WebAppResult;
    const out = collectTechInventory(fp({ name: "Drupal", version: "9" }, { name: "jQuery", version: null }), webapp);
    expect(out.map((o) => [o.tech, o.version, o.source, o.reportedVulnerable])).toEqual([
      ["Drupal", "9.5.11", "webapp", false],
      ["jQuery", "1.12.4", "webapp", true],
      ["Joomla", null, "webapp", false],
      ["Moment.js", null, "webapp", false],
    ]);
  });

  it("tolerates scans stored before a module existed", () => {
    expect(collectTechInventory(undefined, undefined)).toEqual([]);
    expect(collectTechInventory({ status: "error", note: "x" }, { status: "error", note: "y" })).toEqual([]);
  });
});
