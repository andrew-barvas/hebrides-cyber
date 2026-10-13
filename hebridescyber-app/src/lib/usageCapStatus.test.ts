import { describe, it, expect } from "vitest";
import { capStatus } from "./usageCapStatus";

describe("capStatus", () => {
  it("is unknown when the cap couldn't be determined", () => {
    expect(capStatus(0, null)).toBe("unknown");
    expect(capStatus(5, null)).toBe("unknown");
  });

  it("is at when count has reached or passed the cap", () => {
    expect(capStatus(3, 3)).toBe("at");
    expect(capStatus(4, 3)).toBe("at");
  });

  it("is at for a zero cap regardless of count", () => {
    expect(capStatus(0, 0)).toBe("at");
  });

  it("is near at or above the 80% threshold", () => {
    expect(capStatus(12, 15)).toBe("near");
    expect(capStatus(8, 10)).toBe("near");
  });

  it("is ok below the threshold", () => {
    expect(capStatus(1, 15)).toBe("ok");
    expect(capStatus(0, 3)).toBe("ok");
  });
});
