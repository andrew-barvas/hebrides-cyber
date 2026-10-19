import { describe, it, expect, vi, afterEach } from "vitest";
import { checkFingerprint, DETECTABLE_TECHNOLOGIES, distroFromHeader, getCmsType, type DetectedTech } from "./fingerprint";

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
    expect(getCmsType([tech("PrestaShop")])).toBe("prestashop");
    expect(getCmsType([tech("OpenCart")])).toBe("opencart");
    expect(getCmsType([tech("TYPO3")])).toBe("typo3");
    expect(getCmsType([tech("Umbraco")])).toBe("umbraco");
    expect(getCmsType([tech("Craft CMS")])).toBe("craft");
    expect(getCmsType([tech("Moodle")])).toBe("moodle");
  });

  it("keeps the established CMSes ahead of the newer ones", () => {
    expect(getCmsType([tech("Moodle"), tech("TYPO3"), tech("Drupal")])).toBe("drupal");
    expect(getCmsType([tech("Moodle"), tech("TYPO3")])).toBe("typo3");
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

describe("checkFingerprint: PrestaShop, OpenCart, TYPO3, Umbraco, Craft CMS and Moodle", () => {
  afterEach(() => vi.unstubAllGlobals());

  const detect = async (body: string, headers: Record<string, string> = {}) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { headers })));
    const result = await checkFingerprint("https://example.com");
    return result.status === "checked" ? result.technologies : [];
  };
  const one = async (name: string, body: string, headers: Record<string, string> = {}) => (await detect(body, headers)).find((t) => t.name === name);

  it("recognises PrestaShop 1.6 and 1.7+", async () => {
    expect(await one("PrestaShop", '<meta name="generator" content="PrestaShop" />')).toMatchObject({ category: "E-commerce", version: null });
    expect(await one("PrestaShop", "<script>var prestashop = {\"cart\":{}};</script>")).toBeDefined();
    expect(await one("PrestaShop", '<link href="/modules/ps_mainmenu/ps_mainmenu.css">')).toBeDefined();
  });

  it("recognises OpenCart from its catalog assets", async () => {
    expect(await one("OpenCart", '<link href="catalog/view/theme/default/stylesheet/stylesheet.css" rel="stylesheet">')).toBeDefined();
    expect(await one("OpenCart", '<script src="/catalog/view/javascript/jquery/jquery-3.7.1.min.js"></script>')).toBeDefined();
  });

  it("recognises TYPO3 and reads the version only when the page prints one", async () => {
    expect(await one("TYPO3", '<link href="/typo3temp/assets/compressed/merged.css">')).toMatchObject({ version: null });
    expect(await one("TYPO3", '<meta name="generator" content="TYPO3 CMS" />')).toMatchObject({ version: null });
    expect(await one("TYPO3", '<meta name="generator" content="TYPO3 6.2 CMS" />')).toMatchObject({ version: "6.2" });
    expect(await one("TYPO3", '<script src="/typo3conf/ext/site/app.js"></script>')).toBeDefined();
  });

  it("recognises Umbraco, with the version from X-Umbraco-Version when sent", async () => {
    expect(await one("Umbraco", '<script src="/umbraco/lib/jquery/jquery.min.js"></script>')).toMatchObject({ version: null });
    expect(await one("Umbraco", "<html></html>", { "x-umbraco-version": "8.18.14" })).toMatchObject({ version: "8.18.14", source: "header" });
  });

  it("recognises Craft CMS from its header or control-panel assets", async () => {
    expect(await one("Craft CMS", "<html></html>", { "x-powered-by": "Craft CMS" })).toBeDefined();
    expect(await one("Craft CMS", '<link href="/cpresources/12ab34/main.css">')).toBeDefined();
  });

  it("recognises Moodle as a learning platform", async () => {
    expect(await one("Moodle", `<script>//<![CDATA[
var M = {}; M.yui = {};
M.cfg = {"wwwroot":"https://lms.example.edu"};
</script>`)).toMatchObject({ category: "LMS" });
    expect(await one("Moodle", '<meta name="keywords" content="moodle, Course | Example College" />')).toBeDefined();
    expect(await one("Moodle", '<link rel="stylesheet" href="https://lms.example.edu/theme/styles.php/boost/1700000000/all">')).toBeDefined();
  });

  // Each of these mentions a platform's name or path text without being it.
  it("does not label other sites", async () => {
    const lookalikes = [
      "<article><h1>Migrating from TYPO3 to WordPress</h1><p>Look in typo3conf and fileadmin.</p></article>",
      "<p>Our PrestaShop and OpenCart themes, plus a Moodle plugin.</p>",
      '<script src="/_next/static/chunks/main.js"></script><div id="__next"></div>',
      '<link href="/wp-content/themes/shop/style.css"><p>catalog view theme</p>',
      "<script>const config = { cfg: {} }; M.cfgs = 1;</script>",
      '<link href="/assets/cpanel/main.css"><script src="/lib/javascript.js"></script>',
    ];
    for (const body of lookalikes) {
      const names = (await detect(body)).map((t) => t.name);
      for (const cms of ["PrestaShop", "OpenCart", "TYPO3", "Umbraco", "Craft CMS", "Moodle"]) expect(names, body).not.toContain(cms);
    }
    expect(await one("Craft CMS", "<html></html>", { "x-powered-by": "PHP/8.2.12" })).toBeUndefined();
  });

  it("lists each new technology once as detectable", () => {
    for (const name of ["PrestaShop", "OpenCart", "TYPO3", "Umbraco", "Craft CMS", "Moodle"]) {
      expect(DETECTABLE_TECHNOLOGIES.filter((n) => n === name)).toHaveLength(1);
    }
    expect(new Set(DETECTABLE_TECHNOLOGIES).size).toBe(DETECTABLE_TECHNOLOGIES.length);
  });
});
