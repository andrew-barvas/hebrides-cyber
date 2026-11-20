import { describe, expect, it } from "vitest";
import { assessDbSize, sizeReport } from "./dbSize";

const MB = 1024 * 1024;

describe("assessDbSize", () => {
  it("is ok below 70%, warns from 70%, fails from 85% of the Free plan's 500 MB", () => {
    expect(assessDbSize(15 * MB)).toMatchObject({ level: "ok", usedMb: 15, limitMb: 500, percent: 3 });
    expect(assessDbSize(350 * MB).level).toBe("warn");
    expect(assessDbSize(425 * MB).level).toBe("fail");
    expect(assessDbSize(629.3 * MB)).toMatchObject({ level: "fail", percent: 125.9 });
  });
});

describe("sizeReport", () => {
  it("leads with the headline and lists the largest tables", () => {
    const report = sizeReport(assessDbSize(629.3 * MB), [{ schema: "public", table: "cve_cpe_matches", totalBytes: 437.6 * MB, dataBytes: 329.1 * MB, indexBytes: 108.3 * MB, rows: 2195167 }]);
    expect(report.split("\n")[0]).toBe("🛑 **Database: 629.3 MB of 500 MB (125.9%)**");
    expect(report).toContain("| public.cve_cpe_matches | 437.6 MB | 329.1 MB | 108.3 MB | 2,195,167 |");
  });
});
