import { describe, it, expect, vi, afterEach } from "vitest";
import { checkFingerprint, getCmsType, type DetectedTech } from "./fingerprint";

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

describe("checkFingerprint — Azure App Service", () => {
  afterEach(() => vi.unstubAllGlobals());

  // Azure Static Web Apps sends no x-azure-ref; its ARR affinity cookie is the
  // signal deepTls.ts uses to know TLS is platform-managed.
  it("detects Azure's platform from the ARR affinity cookie", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html></html>", { headers: { "set-cookie": "ARRAffinity=abc; path=/; secure; httponly" } })));
    const result = await checkFingerprint("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status === "checked") expect(result.technologies.map((t) => t.name)).toContain("Azure App Service");
  });

  it("doesn't claim Azure without the cookie", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html></html>", { headers: { "set-cookie": "session=abc; path=/" } })));
    const result = await checkFingerprint("https://example.com");
    if (result.status === "checked") expect(result.technologies.map((t) => t.name)).not.toContain("Azure App Service");
  });
});
