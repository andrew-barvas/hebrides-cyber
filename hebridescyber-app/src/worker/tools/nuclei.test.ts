import { describe, it, expect } from "vitest";
import { buildTagArgument, parseNucleiOutput } from "./nuclei";

describe("buildTagArgument", () => {
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
