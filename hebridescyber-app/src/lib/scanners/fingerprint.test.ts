import { describe, it, expect } from "vitest";
import { getCmsType, type DetectedTech } from "./fingerprint";

function tech(name: string): DetectedTech {
  return { name, category: "CMS", version: null, confidence: "high", source: "html" };
}

describe("getCmsType", () => {
  it("returns null when no CMS technology is detected", () => {
    expect(getCmsType([])).toBeNull();
    expect(getCmsType([tech("Nginx"), tech("PHP")])).toBeNull();
  });

  it("detects each supported CMS from its technology name", () => {
    expect(getCmsType([tech("WordPress")])).toBe("wordpress");
    expect(getCmsType([tech("Joomla")])).toBe("joomla");
    expect(getCmsType([tech("Drupal")])).toBe("drupal");
    expect(getCmsType([tech("Magento")])).toBe("magento");
    expect(getCmsType([tech("Ghost")])).toBe("ghost");
  });

  it("ignores unrelated technologies alongside a real CMS match", () => {
    expect(getCmsType([tech("Nginx"), tech("jQuery"), tech("WordPress")])).toBe("wordpress");
  });

  it("breaks ties deterministically when multiple CMS technologies are present", () => {
    // Practically impossible on a real target, but the precedence order
    // must stay stable rather than depend on array iteration order.
    expect(getCmsType([tech("Ghost"), tech("WordPress")])).toBe("wordpress");
    expect(getCmsType([tech("Magento"), tech("Joomla")])).toBe("joomla");
  });
});
