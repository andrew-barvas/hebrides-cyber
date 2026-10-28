import { describe, it, expect } from "vitest";
import { buildInteractshArgs, buildNucleiArgs, buildTagArgument, parseNucleiOutput } from "./nuclei";

describe("buildTagArgument", () => {
  it("scopes nuclei to the newer CMS platforms by their real template tags", () => {
    const tags = buildTagArgument(["PrestaShop", "OpenCart", "TYPO3", "Umbraco", "Craft CMS", "Moodle"]).split(",");
    expect(tags).toEqual(expect.arrayContaining(["prestashop", "opencart", "typo3", "umbraco", "craftcms", "moodle"]));
  });

  it("always includes the baseline tags, incl. ssrf/oast out-of-band testing", () => {
    const tags = buildTagArgument([]).split(",");
    expect(tags).toEqual(expect.arrayContaining(["cve", "exposure", "misconfig", "default-login", "takeover", "ssrf", "oast"]));
  });

  it("adds tags mapped from detected technologies", () => {
    const tags = buildTagArgument(["WordPress", "Nginx"]).split(",");
    expect(tags).toContain("wordpress");
    expect(tags).toContain("wp-plugin");
    expect(tags).toContain("nginx");
  });

  it("contributes nothing for a technology outside the map, without erroring", () => {
    const tags = buildTagArgument(["SomeUnmappedFramework"]).split(",");
    expect(tags).toEqual(expect.arrayContaining(["cve", "exposure", "misconfig", "default-login", "takeover", "ssrf", "oast"]));
    expect(tags).not.toContain("SomeUnmappedFramework");
  });

  it("deduplicates tags reachable via more than one technology", () => {
    const tags = buildTagArgument(["ASP.NET"]).split(",");
    expect(tags.filter((t) => t === "dotnet")).toHaveLength(1);
  });
});

describe("parseNucleiOutput", () => {
  it("parses an SSRF/OAST finding the same as any other nuclei finding", () => {
    // Real shape nuclei writes when an interactsh-confirmed template
    // matches — the JSON carries no special marker for an OOB-confirmed
    // finding; nuclei itself already verified the callback before ever
    // including the entry here.
    const raw = JSON.stringify([
      {
        "template-id": "zzzcms-ssrf",
        info: { name: "ZzzCMS 1.75 - Server-Side Request Forgery", severity: "high", classification: { "cve-id": null } },
        "matched-at": "https://example.com/plugins/ueditor/php/controller.php",
        description: "ZzzCMS is vulnerable to SSRF.",
      },
    ]);
    const findings = parseNucleiOutput(raw, "https://example.com");
    expect(findings).toEqual([
      {
        severity: "high",
        title: "ZzzCMS 1.75 - Server-Side Request Forgery",
        detail: "ZzzCMS is vulnerable to SSRF.",
        templateId: "zzzcms-ssrf",
      },
    ]);
  });
});

describe("buildInteractshArgs", () => {
  it("adds nothing by default, so nuclei keeps its public collaborator pool", () => {
    expect(buildInteractshArgs({})).toEqual([]);
  });

  it("points nuclei at a self-hosted server, with an optional token", () => {
    expect(buildInteractshArgs({ INTERACTSH_SERVER: "oast.example.co.uk" })).toEqual(["-iserver", "oast.example.co.uk"]);
    expect(buildInteractshArgs({ INTERACTSH_SERVER: "oast.example.co.uk", INTERACTSH_TOKEN: " s3cret " })).toEqual(["-iserver", "oast.example.co.uk", "-itoken", "s3cret"]);
  });

  it("accepts a URL form and a port, normalised to a host", () => {
    expect(buildInteractshArgs({ INTERACTSH_SERVER: "https://oast.example.co.uk/" })).toEqual(["-iserver", "oast.example.co.uk"]);
    expect(buildInteractshArgs({ INTERACTSH_SERVER: "oast.example.co.uk:8443" })).toEqual(["-iserver", "oast.example.co.uk:8443"]);
  });

  it.each(["", "   ", "localhost", "oast.example.com; rm -rf /", "-ni", "a b.com", "oast.example.com/path", "http://", "x".repeat(300) + ".com"])(
    "ignores an invalid server %j rather than passing it to the tool",
    (server) => {
      expect(buildInteractshArgs({ INTERACTSH_SERVER: server, INTERACTSH_TOKEN: "t" })).toEqual([]);
    },
  );

  it("DISABLE_OAST=1 turns out-of-band off and wins over a server", () => {
    expect(buildInteractshArgs({ DISABLE_OAST: "1" })).toEqual(["-ni"]);
    expect(buildInteractshArgs({ DISABLE_OAST: "1", INTERACTSH_SERVER: "oast.example.co.uk" })).toEqual(["-ni"]);
  });
});

describe("buildNucleiArgs", () => {
  it("keeps the existing arguments and appends the out-of-band ones", () => {
    expect(buildNucleiArgs("https://t.example", "cve,ssrf", "/tmp/o.json", {})).toEqual([
      "-target", "https://t.example", "-tags", "cve,ssrf", "-json-export", "/tmp/o.json", "-silent", "-timeout", "10",
    ]);
    expect(buildNucleiArgs("https://t.example", "cve", "/tmp/o.json", { INTERACTSH_SERVER: "oast.example.co.uk" }).slice(-2)).toEqual(["-iserver", "oast.example.co.uk"]);
  });
});
