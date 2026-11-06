// Two scan-worker paths run the same queue: the always-on Container Apps Job
// (Dockerfile `scan-worker` stage + azure/terraform/scan-workers.tf) and the
// GitHub Actions fallback (scheduled-scans.yml). These checks keep them, and
// tool-integration.yml's real-binary tests, on the same tools and settings —
// the failure each one guards against is silent: a tool the image never got,
// or a secret the job never passed, only shows up as not_configured results.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const APP = process.cwd();
const read = (...p: string[]) => readFileSync(path.join(APP, ...p), "utf8").replace(/\r\n/g, "\n");

const scanTools = read("docker", "scan-tools.sh");
const dockerfile = read("Dockerfile");
const terraform = read("azure", "terraform", "scan-workers.tf");
const scheduled = read("..", ".github", "workflows", "scheduled-scans.yml");
const toolIntegration = read("..", ".github", "workflows", "tool-integration.yml");

/** NAME=value assignments at the top level of scan-tools.sh. */
function scriptPins(): Map<string, string> {
  const pins = new Map<string, string>();
  for (const m of scanTools.matchAll(/^([A-Z_]+_(?:VERSION|SHA256|TAG|COMMIT))=(\S+)$/gm)) pins.set(m[1], m[2]);
  return pins;
}

/** NAME: value env entries in a workflow. */
function workflowPins(text: string): Map<string, string> {
  const pins = new Map<string, string>();
  for (const m of text.matchAll(/^\s+([A-Z_]+_(?:VERSION|SHA256)): (\S+)$/gm)) pins.set(m[1], m[2]);
  return pins;
}

describe("docker/scan-tools.sh pins", () => {
  const pins = scriptPins();

  it("pins every downloaded release binary by version and SHA-256", () => {
    for (const [name] of pins) {
      if (!name.endsWith("_SHA256")) continue;
      const version = name.replace(/_SHA256$/, "_VERSION");
      expect(pins.has(version), `${name} has no ${version}`).toBe(true);
      expect(pins.get(name)).toMatch(/^[0-9a-f]{64}$/);
    }
    // dalfox, nuclei, subfinder, httpx, katana, naabu, ffuf, gitleaks, trivy, opengrep, gospider, kiterunner.
    expect([...pins.keys()].filter((k) => k.endsWith("_SHA256")).length).toBeGreaterThanOrEqual(12);
  });

  it("verifies every download before unpacking it", () => {
    // Each binary is fetched through fetch(), which runs sha256sum -c and deletes on mismatch.
    expect(scanTools).toMatch(/sha256sum -c -/);
    expect(scanTools).not.toMatch(/curl -fsSL [^\n]*\| *(ba)?sh/);
    for (const name of [...pins.keys()].filter((k) => k.endsWith("_SHA256"))) {
      expect(scanTools, `${name} is never checked`).toContain(`"$${name}"`);
    }
  });

  it("matches the versions tool-integration.yml proves against the real binaries", () => {
    const tested = workflowPins(toolIntegration);
    expect(tested.size).toBeGreaterThan(0);
    for (const [name, value] of tested) {
      expect(pins.get(name), `${name} differs from tool-integration.yml`).toBe(value);
    }
  });

  it.each([
    ["whatwaf", "WHATWAF_TAG", "--branch v1.9 https://github.com/Ekultek/WhatWaf.git"],
    ["testssl.sh", "TESTSSL_TAG", "--branch v3.2.4 https://github.com/testssl/testssl.sh.git"],
    ["commix", "COMMIX_TAG", "--branch v4.1 https://github.com/commixproject/commix.git"],
  ])("pins %s to the tag tool-integration.yml checks", (_tool, pin, tested) => {
    expect(toolIntegration).toContain(tested);
    expect(tested).toContain(`--branch ${pins.get(pin)} `);
  });

  it.each([
    ["CMSMAP_COMMIT", (v: string) => `checkout ${v}`],
    ["BADSECRETS_VERSION", (v: string) => `badsecrets==${v}`],
    ["ARJUN_VERSION", (v: string) => `arjun==${v}`],
    ["WPSCAN_VERSION", (v: string) => `wpscan -v ${v}`],
  ])("pins %s to what tool-integration.yml checks", (pin, inWorkflow) => {
    expect(toolIntegration).toContain(inWorkflow(pins.get(pin) ?? "missing"));
  });
});

describe("scheduled-scans.yml (the fallback path)", () => {
  it("installs the tools through the shared script rather than its own copy of the pins", () => {
    expect(scheduled).toContain("run: bash hebridescyber-app/docker/scan-tools.sh all hebridescyber-app");
    expect(scheduled).not.toMatch(/sha256sum -c/);
    expect(workflowPins(scheduled).size).toBe(0);
  });

  it("does not set SCAN_TOOLS_STRICT, so its fail-soft installs stay fail-soft", () => {
    // Mentioned in a comment, never set.
    expect(scheduled).not.toMatch(/SCAN_TOOLS_STRICT\s*[:=]/);
  });
});

describe("scan-worker image", () => {
  it("fails the build on any tool that doesn't install, then checks every tool is present", () => {
    const stage = dockerfile.slice(dockerfile.indexOf("AS scan-worker"), dockerfile.indexOf("AS runner"));
    expect(stage).toContain("ENV SCAN_TOOLS_STRICT=1");
    expect(stage).toContain("scan-tools.sh system /app");
    expect(stage).toContain("scan-tools.sh user /app");
    expect(stage).toContain("scan-tools.sh verify /app");
    expect(stage).toContain("USER scanner");
  });

  it("keeps the web app the last stage, which deploy-containerapp.yml builds by default", () => {
    const stages = [...dockerfile.matchAll(/^FROM \S+ AS (\S+)$/gm)].map((m) => m[1]);
    expect(stages.at(-1)).toBe("runner");
    expect(stages).toContain("scan-worker");
  });

  it("sets the tool paths the workflow sets", () => {
    for (const name of ["TESTSSL_PATH", "KITERUNNER_WORDLIST", "CONTENT_DISCOVERY_WORDLIST"]) {
      expect(scheduled).toContain(`${name}:`);
      expect(dockerfile).toContain(`${name}=`);
    }
  });
});

describe("azure/terraform/scan-workers.tf", () => {
  /** The env names the fallback's worker step passes. */
  function fallbackEnvNames(): string[] {
    const start = scheduled.indexOf("- name: Work the scan job queue");
    const run = scheduled.indexOf("run: npm run queue:run-worker", start);
    const block = scheduled.slice(start, run);
    return [...block.matchAll(/^ {10}([A-Z_]+):/gm)].map((m) => m[1]);
  }

  // Set by the image or its entrypoint rather than by Terraform.
  const FROM_IMAGE = ["WORKER_ID", "ZAP_API_URL", "TESTSSL_PATH", "KITERUNNER_WORDLIST", "CONTENT_DISCOVERY_WORDLIST"];

  it("gives the job every setting the Actions worker gets", () => {
    const names = fallbackEnvNames();
    expect(names).toContain("SUPABASE_SERVICE_ROLE_KEY");
    for (const name of names) {
      if (FROM_IMAGE.includes(name)) continue;
      expect(terraform, `${name} is passed to the Actions worker but not the Container Apps Job`).toContain(name);
    }
  });

  it("runs the same ZAP image digest as the workflow", () => {
    const digest = /zaproxy@sha256:[0-9a-f]{64}/;
    expect(terraform.match(digest)?.[0]).toBe(scheduled.match(digest)?.[0]);
  });

  it("scales on the same rows claim_scan_job() takes", () => {
    expect(terraform).toContain(`custom_rule_type = "postgresql"`);
    expect(terraform).toContain("SELECT COUNT(*) FROM public.scan_jobs WHERE status = 'pending'");
  });

  it("keeps the static IP behind a switch that is off by default (no NAT gateway bill until it is needed)", () => {
    expect(terraform).toMatch(/variable "scan_static_egress_ip" \{[^}]*type\s*=\s*bool[^}]*default\s*=\s*false/);
  });

  it("gates every paid network resource on that switch", () => {
    for (const resource of [
      `"azurerm_public_ip" "scan_egress"`,
      `"azurerm_nat_gateway" "scan_egress"`,
      `"azurerm_nat_gateway_public_ip_association" "scan_egress"`,
      `"azurerm_subnet_nat_gateway_association" "scan_workers"`,
    ]) {
      expect(terraform, `${resource} is not gated`).toMatch(
        new RegExp(`resource ${resource.replace(/"/g, '\\"')} \\{\\s*count = var\\.scan_static_egress_ip \\? 1 : 0`)
      );
    }
  });

  it("with the switch on, routes egress through a NAT gateway on one static Standard IP that can't be destroyed by accident", () => {
    const ip = terraform.slice(terraform.indexOf(`resource "azurerm_public_ip" "scan_egress"`));
    expect(ip.slice(0, ip.indexOf("\n}\n"))).toMatch(/allocation_method\s*=\s*"Static"[\s\S]*prevent_destroy = true/);
    expect(terraform).toMatch(/infrastructure_subnet_id\s*=\s*var\.scan_static_egress_ip \? azurerm_subnet\.scan_workers\[0\]\.id : null/);
  });

  it("times a replica out well before reset_stale_scan_jobs() would re-queue its job (390 minutes)", () => {
    const timeout = Number(terraform.match(/replica_timeout_in_seconds = (\d+)/)?.[1]);
    expect(timeout).toBeGreaterThan(25 * 60);
    expect(timeout).toBeLessThan(390 * 60);
  });
});
