import { describe, it, expect, vi, afterEach } from "vitest";
import { checkFingerprint, distroFromHeader, getCmsType, type DetectedTech } from "./fingerprint";

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
    expect(getCmsType([tech("Shopify")])).toBe("shopify");
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

describe("checkFingerprint — Django", () => {
  afterEach(() => vi.unstubAllGlobals());

  const names = async (body: string, headers: Record<string, string>) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { headers })));
    const result = await checkFingerprint("https://example.com");
    return result.status === "checked" ? result.technologies.map((t) => t.name) : [];
  };

  // Regression: our own Next.js site was reported as "Django" because the
  // rule matched on X-Frame-Options / X-Content-Type-Options, which every
  // well-configured site sends.
  it("does not call a site Django just for sending standard security headers", async () => {
    expect(await names("<html></html>", { "x-frame-options": "SAMEORIGIN", "x-content-type-options": "nosniff" })).not.toContain("Django");
  });

  it("still detects Django from its CSRF form field", async () => {
    expect(await names('<form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>', {})).toContain("Django");
  });
});

describe("distroFromHeader", () => {
  it.each([
    ["Apache/2.4.41 (Ubuntu)", "Ubuntu"],
    ["PHP/7.4.3-4ubuntu2.19", "Ubuntu"],
    ["Apache/2.4.62 (Debian)", "Debian"],
    ["Apache/2.4.37 (Red Hat Enterprise Linux)", "Red Hat"],
    ["Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips", "CentOS"],
    ["nginx/1.18.0", null],
    ["Apache", null],
  ])("%s → %s", (header, distro) => {
    expect(distroFromHeader(header)).toBe(distro);
  });
});

describe("checkFingerprint — packaged versions", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("records the distribution named in the version header", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html></html>", { headers: { server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/8.1.2" } })));
    const result = await checkFingerprint("https://example.com");
    if (result.status !== "checked") throw new Error("not checked");
    expect(result.technologies.find((t) => t.name === "Apache")).toMatchObject({ version: "2.4.41", packagedBy: "Ubuntu" });
    expect(result.technologies.find((t) => t.name === "PHP")).not.toHaveProperty("packagedBy");
  });
});
