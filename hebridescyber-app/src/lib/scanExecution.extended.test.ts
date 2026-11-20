// runExtendedTools: how each extended tool's raw result becomes findings, and
// what a tool that throws, is disabled, or has nothing to check leaves in
// `extended`. Every tool module is mocked; `replies` holds what each returns.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { replies, calls, customChecksMock, metadataMock } = vi.hoisted(() => ({
  replies: {} as Record<string, unknown>,
  calls: {} as Record<string, unknown[][]>,
  customChecksMock: vi.fn(async () => [] as unknown[]),
  metadataMock: vi.fn(),
}));

/** A tool function that records its arguments and answers replies[name] (rejecting when it is an Error). */
function tool(name: string) {
  return async (...args: unknown[]) => {
    (calls[name] ??= []).push(args);
    const r = replies[name];
    if (r instanceof Error) throw r;
    return r;
  };
}

vi.mock("../worker/tools/nuclei", () => ({ runNuclei: tool("nuclei") }));
vi.mock("../worker/tools/zap", () => ({ runZap: tool("zap") }));
vi.mock("../worker/tools/sqlmap", () => ({ runSqlmap: tool("sqlmap") }));
vi.mock("../worker/tools/commix", () => ({ runCommix: tool("commix") }));
vi.mock("../worker/tools/dalfox", () => ({ runDalfox: tool("dalfox") }));
vi.mock("../worker/tools/nmap", () => ({ runNmap: tool("nmap") }));
vi.mock("../worker/tools/networkExposure", () => ({ runNetworkExposure: tool("networkExposure") }));
vi.mock("./objectStore", () => ({ cveIndexObjectStore: vi.fn(async () => ({})) }));
vi.mock("./cveIndex", () => ({ createCveIndex: vi.fn(() => ({})) }));
vi.mock("./cveIndexObjects", () => ({ objectCveIndexStore: vi.fn(() => ({})) }));
vi.mock("./scanners/subdomains", () => ({ runSubdomainDiscovery: tool("subdomains") }));
vi.mock("./scanners/hostProbe", async (orig) => ({ ...(await orig<typeof import("./scanners/hostProbe")>()), runHttpProbe: tool("httpx") }));
vi.mock("../worker/tools/contentDiscovery", async (orig) => ({ ...(await orig<typeof import("../worker/tools/contentDiscovery")>()), runContentDiscovery: tool("contentDiscovery") }));
vi.mock("../worker/tools/credentialSpray", async (orig) => ({ ...(await orig<typeof import("../worker/tools/credentialSpray")>()), runCredentialSpray: tool("credentialSpray") }));
vi.mock("./scanners/deepTls", async (orig) => ({ ...(await orig<typeof import("./scanners/deepTls")>()), runDeepTls: tool("deepTls") }));
vi.mock("./scanners/secretScan", () => ({ scanRepositoryForSecrets: tool("secretScan") }));
vi.mock("./scanners/dependencyManifest", () => ({ scanDependencyManifest: tool("dependencyManifest") }));
vi.mock("./scanners/dockerBaseImage", () => ({ scanDockerBaseImage: tool("dockerBaseImage") }));
vi.mock("./scanners/trivyScan", () => ({ scanTrivyImage: tool("trivyImage"), scanTrivyConfig: tool("trivyConfig") }));
vi.mock("../worker/tools/sast", () => ({ runSast: tool("sast") }));
vi.mock("../worker/tools/workflowSecurity", () => ({ runWorkflowSecurity: tool("workflowSecurity") }));
vi.mock("../worker/tools/scorecard", () => ({ runScorecard: tool("scorecard") }));
vi.mock("./scanners/authenticatedCheck", async (orig) => ({ ...(await orig<typeof import("./scanners/authenticatedCheck")>()), checkAuthenticated: tool("authCheck") }));
vi.mock("../worker/tools/whatwaf", () => ({ runWhatWaf: tool("whatwaf") }));
vi.mock("../worker/tools/wpscan", () => ({ runWpScanCli: tool("wpscan") }));
vi.mock("../worker/tools/cmsmap", () => ({ runCmsMap: tool("cmsmap") }));
vi.mock("../worker/tools/photon", () => ({ runPhoton: tool("photon") }));
vi.mock("../worker/tools/gospider", () => ({ runGospider: tool("gospider") }));
vi.mock("../worker/tools/zapAjaxSpider", () => ({ runZapAjaxSpider: tool("zapAjaxSpider") }));
vi.mock("../worker/tools/metadataLeak", () => ({ runMetadataLeakCheck: metadataMock }));
vi.mock("../worker/tools/kiterunner", () => ({ runKiterunner: tool("kiterunner") }));
vi.mock("../worker/tools/arjun", () => ({ runArjun: tool("arjun") }));
vi.mock("../worker/tools/sessionCheck", () => ({ runSessionCheck: tool("sessionCheck") }));
vi.mock("../worker/tools/jwtAnalysis", () => ({ runJwtAnalysis: tool("jwtAnalysis") }));
vi.mock("../worker/tools/strix", () => ({ runStrix: tool("strix") }));
vi.mock("../worker/tools/cairn", () => ({ runCairn: tool("cairn") }));
vi.mock("./scanners/apiSpec", () => ({ checkApiSpecInjection: tool("apiSpecInjection") }));
vi.mock("../worker/tools/badsecrets", () => ({ runBadsecrets: tool("badsecrets") }));
vi.mock("../worker/tools/katana", () => ({ runKatana: tool("katana") }));
vi.mock("./customChecks", () => ({ runCustomChecksForOwner: customChecksMock }));

import { runExtendedTools } from "./scanExecution";
import { EXTENDED_TOOL_NAMES, type ExtendedToolName } from "./scanProfiles";
import type { Finding } from "./scanners";

const TARGET = "https://shop.example";
const DB = {} as never;
const f = (checkId: string, severity: Finding["severity"] = "low"): Finding => ({ checkId, severity, title: checkId, detail: "", remediation: "" });

function allTools(on = true): Record<ExtendedToolName, boolean> {
  return Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, on])) as Record<ExtendedToolName, boolean>;
}

/** Every tool completing with something to report. */
function completedReplies() {
  Object.assign(replies, {
    nuclei: { status: "completed", findings: [{ templateId: "exposed-panel", title: "Exposed panel", severity: "high", detail: "d", cveIds: [] }, { templateId: "", title: "No template", severity: "low", detail: "d" }] },
    zap: { status: "completed", alerts: [], findings: [f("zap.alert:10020")] },
    sqlmap: {
      status: "completed",
      vulnerable: true,
      findings: [
        { parameter: "id", place: "GET", dbms: "MySQL", url: `${TARGET}/item?id=1`, techniques: ["boolean-based blind"] },
        { parameter: "id", place: "POST", dbms: null, url: "", techniques: [] },
      ],
    },
    commix: { status: "completed", vulnerable: true, findings: [{ parameter: "host", place: "GET" }, { parameter: "host", place: "COOKIE" }] },
    dalfox: { status: "completed", findings: [{ param: "q", severity: "high", payload: "<x>", evidence: "reflected" }] },
    nmap: { status: "completed", host: TARGET, ports: [{ port: 6379, protocol: "tcp", service: "redis" }, { port: 443, protocol: "tcp", service: "https" }] },
    networkExposure: {
      status: "completed",
      host: TARGET,
      ports: [
        { port: 3306, protocol: "tcp", service: "mysql", version: "8.0.30", risk: "high", reason: "A database should not be public." },
        { port: 22, protocol: "tcp", service: "ssh", version: null, risk: "medium", reason: "Remote login." },
        { port: 443, protocol: "tcp", service: "https", version: null, risk: "info", reason: "" },
      ],
      serviceCves: { services: [], incompleteChecks: [] },
      findings: [f("ssh-audit.weak-kex")],
    },
    subdomains: { status: "completed", total: 2, subdomains: [{ host: "a.shop.example", resolves: true }, { host: "gone.shop.example", resolves: false }], findings: [f("subdomains.takeover:a")] },
    httpx: { status: "completed", results: [] },
    contentDiscovery: { status: "completed", hits: [] },
    credentialSpray: { status: "completed", found: [] },
    deepTls: { status: "completed", host: TARGET, findings: [f("deep-tls.weak-cipher")] },
    secretScan: { status: "completed", repo: "acme/site", findings: [f("secret-scan.aws-key")] },
    dependencyManifest: { status: "completed", repo: "acme/site", findings: [f("dependency.lodash")] },
    dockerBaseImage: { status: "completed", repo: "acme/site", findings: [f("docker.base-eol")] },
    trivyImage: { status: "completed", repo: "acme/site", findings: [f("trivy-image.cve")] },
    trivyConfig: { status: "completed", repo: "acme/site", findings: [f("trivy-config.k8s")] },
    sast: { status: "completed", repo: "acme/site", findings: [f("sast.sql-concat")] },
    workflowSecurity: { status: "completed", repo: "acme/site", findings: [f("workflow-security.unpinned")] },
    scorecard: { status: "completed", repo: "acme/site", findings: [f("scorecard.branch-protection")] },
    authCheck: { status: "not_applicable", note: "No credential." },
    whatwaf: { status: "completed", waf: null, vendor: null, evidence: "No WAF headers." },
    wpscan: {
      status: "completed",
      findings: [
        { type: "file", title: "WordPress config backup found", detail: "d", severity: "high", slug: "wp-config" },
        { type: "file", title: "Public database export", detail: "d", severity: "" },
        { type: "file", title: "TimThumb script present", detail: "d", severity: "medium", slug: "timthumb" },
        { type: "vulnerability", title: "Theme XSS", detail: "d", severity: "medium", slug: "twentyten", fixedIn: "3.1", cveIds: ["CVE-2024-0001"] },
        { type: "vulnerability", title: "Plugin issue without slug", detail: "d", severity: "low" },
      ],
    },
    cmsmap: {
      status: "completed",
      cmsType: "wordpress",
      findings: [
        { type: "vulnerability", title: "Old core", detail: "d", severity: "high", checkName: "core-version" },
        { type: "misconfiguration", title: "Directory listing on uploads", detail: "d", severity: "" },
      ],
    },
    photon: {
      status: "completed",
      assets: [
        ...Array.from({ length: 6 }, (_, i) => ({ type: "email", value: `p${i}@shop.example` })),
        { type: "js-endpoint", value: "/api/cart" },
        { type: "url", value: `${TARGET}/brochure.pdf` },
      ],
    },
    gospider: {
      status: "completed",
      endpoints: [
        ...Array.from({ length: 6 }, (_, i) => ({ type: "js-endpoint", value: `/api/v${i}`, source: "js" })),
        { type: "aws-s3", value: "shop-assets.s3.amazonaws.com", source: "js" },
        { type: "url", value: `${TARGET}/menu.docx`, source: "href" },
      ],
    },
    zapAjaxSpider: { status: "completed", urls: [`${TARGET}/#/account`] },
    kiterunner: { status: "completed", endpoints: Array.from({ length: 6 }, (_, i) => ({ method: "GET", path: `/api/internal/${i}`, statusCode: 200 })) },
    arjun: { status: "completed", parameters: [{ url: `${TARGET}/search`, method: "GET", params: ["debug", "admin"] }, { url: `${TARGET}/none`, method: "GET", params: [] }] },
    sessionCheck: {
      status: "completed",
      findings: ["no-rate-limit", "session-fixation", "idor-indicator", "weak-session-token"].map((type) => ({ type, detail: "d", url: `${TARGET}/login` })),
    },
    jwtAnalysis: {
      status: "completed",
      findings: ["none-algorithm", "no-expiration", "weak-secret", "sent-over-http", "exposed-in-url", "something-new"].map((type) => ({ type, detail: "d", url: `${TARGET}/api` })),
    },
    strix: {
      status: "completed",
      findings: [
        { severity: "high", title: "IDOR on orders", detail: "d", vulnClass: "idor", exploit: "GET /orders/2", agentRemediation: "" },
        { severity: "", title: "Agent fix", detail: "d", vulnClass: "", exploit: "", agentRemediation: "Check ownership." },
      ],
    },
    cairn: {
      status: "completed",
      findings: [
        { severity: "critical", title: "Chained takeover", detail: "d", vulnClass: "rce", evidence: "uid=33", endpoint: "/upload", cveIds: ["CVE-2024-0002"], exploitSteps: ["upload", "execute"] },
        { severity: "", title: "Weak spot", detail: "d", vulnClass: "", evidence: "", endpoint: "/", cveIds: [], exploitSteps: [] },
      ],
    },
    apiSpecInjection: { status: "completed", findings: [f("api-spec.sqli:id")], endpointsTested: 3, specSource: "openapi" },
    badsecrets: { status: "completed", findings: [f("badsecrets.flask-key")] },
    katana: { status: "partial", findings: [f("katana.form-without-csrf")] },
  });
}

beforeEach(() => {
  for (const k of Object.keys(replies)) delete replies[k];
  for (const k of Object.keys(calls)) delete calls[k];
  customChecksMock.mockReset().mockResolvedValue([f("custom.owner-check")]);
  metadataMock.mockReset().mockResolvedValue({
    status: "completed",
    findings: ["email", "internal-ip", "path", "author", "software", "gps"].map((type) => ({ type, value: "v", url: `${TARGET}/brochure.pdf` })),
  });
});

const ids = (findings: Finding[]) => findings.map((x) => x.checkId);

describe("runExtendedTools: every tool completed", () => {
  it("turns each tool's result into findings with stable check ids", async () => {
    completedReplies();
    const { findings, extended, supersedesReconSubdomains } = await runExtendedTools(
      TARGET, "acme/site", null, ["WordPress"], allTools(), DB, "owner-1", [], false, [`${TARGET}/menu.docx`],
    );
    const got = ids(findings);

    expect(got).toEqual(expect.arrayContaining([
      "nuclei.finding:exposed-panel",
      "nuclei.finding:No template",
      "custom.owner-check",
      "zap.alert:10020",
      "sqlmap.sqli:id",
      "sqlmap.sqli:id:post",
      "commix.command-injection:host",
      "commix.command-injection:host:cookie",
      "dalfox.reflected-xss:q",
      "nmap.dangerous-port:6379",
      "network-exposure.open-port:3306",
      "network-exposure.open-port:22",
      "ssh-audit.weak-kex",
      "subdomains.takeover:a",
      "deep-tls.weak-cipher",
      "secret-scan.aws-key",
      "dependency.lodash",
      "docker.base-eol",
      "trivy-image.cve",
      "trivy-config.k8s",
      "sast.sql-concat",
      "workflow-security.unpinned",
      "scorecard.branch-protection",
      "badsecrets.flask-key",
      "katana.form-without-csrf",
      "whatwaf.no-waf",
      "wpscan.config-backup:wp-config",
      "wpscan.db-export:public-database-export",
      "wpscan.timthumb:timthumb",
      "wpscan.theme-vulnerability:twentyten",
      "wpscan.theme-vulnerability:plugin-issue-without-slug",
      "cmsmap.vulnerability:core-version",
      "cmsmap.misconfiguration:directory-listing-on-uploads",
      "photon.emails-discovered",
      "photon.js-endpoints-discovered",
      "gospider.js-endpoints-discovered",
      "gospider.aws-s3-reference",
      "zapAjaxSpider.hidden-endpoint",
      "kiterunner.hidden-api-endpoint",
      `arjun.hidden-parameter:${TARGET}/search`,
      `sessionCheck.idor-indicator:${TARGET}/login`,
      `jwt-analysis.none-algorithm:${TARGET}/api`,
      `jwt-analysis.something-new:${TARGET}/api`,
      "strix.finding:idor",
      "strix.finding:Agent fix",
      "cairn.finding:rce",
      "cairn.finding:Weak spot",
      "api-spec.sqli:id",
      `metadataLeak.internal-ip:${TARGET}/brochure.pdf`,
    ]));
    // Expected services (risk "info") and safe nmap ports aren't findings.
    expect(got).not.toContain("network-exposure.open-port:443");
    expect(got).not.toContain("nmap.dangerous-port:443");
    expect(got).not.toContain(`arjun.hidden-parameter:${TARGET}/none`);
    expect(supersedesReconSubdomains).toBe(true);

    const byId = Object.fromEntries(findings.map((x) => [x.checkId, x]));
    expect(byId["sqlmap.sqli:id"].detail).toContain("Techniques that worked: boolean-based blind");
    expect(byId["sqlmap.sqli:id:post"].detail).toContain("DBMS: unknown");
    expect(byId["network-exposure.open-port:3306"].title).toContain("(8.0.30)");
    expect(byId["photon.emails-discovered"].detail).toContain("(+1 more)");
    expect(byId["gospider.js-endpoints-discovered"].detail).toContain("(+1 more)");
    expect(byId["kiterunner.hidden-api-endpoint"].detail).toContain("(+1 more)");
    expect(byId["wpscan.config-backup:wp-config"].severity).toBe("high");
    expect(byId["wpscan.db-export:public-database-export"].severity).toBe("medium"); // blank severity defaults
    expect(byId["cmsmap.misconfiguration:directory-listing-on-uploads"].severity).toBe("medium");
    expect(byId["strix.finding:idor"].detail).toContain("Proof of concept:");
    expect(byId["strix.finding:Agent fix"]).toMatchObject({ severity: "medium", remediation: "Check ownership." });
    expect(byId["cairn.finding:rce"].detail).toMatch(/Evidence: uid=33[\s\S]*Exploit chain:\n1\. upload\n2\. execute/);
    expect(byId["cairn.finding:Weak spot"]).toMatchObject({ severity: "high", cveIds: undefined });
    expect(byId[`jwt-analysis.something-new:${TARGET}/api`]).toMatchObject({ severity: "medium", title: "[JWT] something-new" });
    expect(byId[`metadataLeak.internal-ip:${TARGET}/brochure.pdf`].severity).toBe("medium");
    expect(byId[`metadataLeak.gps:${TARGET}/brochure.pdf`].severity).toBe("low");
    expect(byId[`metadataLeak.software:${TARGET}/brochure.pdf`].severity).toBe("info");

    // httpx probes the target's subdomains that resolve, not the dead one.
    expect(calls.httpx[0]).toEqual([TARGET, ["a.shop.example"]]);
    // The metadata check gets the crawl's, Photon's and Gospider's document links, once each.
    expect(metadataMock).toHaveBeenCalledWith([`${TARGET}/menu.docx`, `${TARGET}/brochure.pdf`]);
    expect((extended as Record<string, { status: string }>).metadataLeak.status).toBe("completed");
  });

  it("reports a detected WAF as information", async () => {
    replies.whatwaf = { status: "completed", waf: "Cloudflare", vendor: "Cloudflare Inc.", evidence: "cf-ray header." };
    const tools = { ...allTools(false), whatwaf: true };
    const { findings } = await runExtendedTools(TARGET, null, null, [], tools, DB, "owner-1");
    expect(findings).toEqual([expect.objectContaining({ checkId: "whatwaf.waf-detected", severity: "info", detail: expect.stringContaining("Cloudflare, Cloudflare Inc.") })]);
  });
});

describe("runExtendedTools: failures and gating", () => {
  it("records a tool that throws as an error, never as a clean result", async () => {
    for (const name of ["nuclei", "zap", "sqlmap", "commix", "dalfox", "nmap", "networkExposure", "subdomains", "deepTls", "secretScan", "dependencyManifest", "dockerBaseImage", "trivyImage", "trivyConfig", "sast", "workflowSecurity", "scorecard", "authCheck", "whatwaf", "wpscan", "cmsmap", "photon", "gospider", "zapAjaxSpider", "kiterunner", "arjun", "sessionCheck", "jwtAnalysis", "strix", "cairn", "apiSpecInjection", "badsecrets", "katana"]) {
      replies[name] = new Error(`${name} crashed`);
    }
    replies.httpx = { status: "completed", results: [] };
    replies.contentDiscovery = { status: "completed", hits: [] };
    replies.credentialSpray = { status: "completed", found: [] };
    const { extended, findings } = await runExtendedTools(TARGET, "acme/site", null, ["WordPress"], allTools(), DB, "owner-1", [], false, null);
    const ext = extended as Record<string, { status: string; note?: string }>;
    for (const name of ["nuclei", "zap", "sqlmap", "subdomains", "secretScan", "whatwaf", "cmsmap", "katana", "apiSpecInjection"]) {
      expect(ext[name]).toMatchObject({ status: "error", note: expect.stringContaining(`${name} crashed`) });
    }
    // Only the account's own checks produced anything.
    expect(ids(findings)).toEqual(["custom.owner-check"]);
    // No crawl and no discovered documents: the metadata check can't claim "none found".
    expect(ext.metadataLeak.status).toBe("error");
  });

  it("leaves disabled tools as not run, and repo checks unconfigured without a linked repository", async () => {
    const { extended, findings, supersedesReconSubdomains } = await runExtendedTools(TARGET, null, null, [], allTools(false), DB, "owner-1");
    const ext = extended as Record<string, { status: string; note?: string }>;
    expect(findings).toEqual([]);
    expect(Object.keys(calls)).toEqual([]);
    expect(ext.secretScan).toMatchObject({ status: "not_configured", note: "No repository linked to this site." });
    expect(ext.dependencyManifest).toMatchObject({ status: "not_applicable", note: "No repository linked to this site." });
    expect(ext.cmsmap).toMatchObject({ status: "not_applicable", note: "No CMS detected." });
    expect(ext.metadataLeak.status).toBe("not_configured");
    expect(supersedesReconSubdomains).toBe(false);
    expect(customChecksMock).not.toHaveBeenCalled();
  });

  it("says a repo check is off by profile when a repository is linked", async () => {
    const { extended } = await runExtendedTools(TARGET, "acme/site", null, ["WordPress"], allTools(false), DB, "owner-1");
    const ext = extended as Record<string, { note?: string }>;
    expect(ext.secretScan.note).toBe("Disabled by scan profile.");
    expect(ext.cmsmap.note).toBe("Disabled by scan profile.");
  });

  it("runs nuclei restricted and skips the account's own checks under a non-intrusive profile", async () => {
    replies.nuclei = { status: "completed", findings: [] };
    replies.zap = { status: "completed", alerts: [], findings: [] };
    const tools = { ...allTools(false), nuclei: true, zap: true };
    await runExtendedTools(TARGET, null, null, ["Next.js"], tools, DB, "owner-1", [], true);
    expect(calls.nuclei[0]).toEqual([TARGET, ["Next.js"], { nonIntrusive: true }]);
    expect(calls.zap[0]).toEqual([TARGET, { passiveOnly: true }]);
    expect(customChecksMock).not.toHaveBeenCalled();
  });

  it("marks the metadata check clean when the crawl worked and found no documents", async () => {
    const { extended } = await runExtendedTools(TARGET, null, null, [], { ...allTools(false), metadataLeak: true }, DB, "owner-1", [], false, []);
    expect((extended as Record<string, unknown>).metadataLeak).toEqual({ status: "completed", findings: [] });
    expect(metadataMock).not.toHaveBeenCalled();
  });

  it("records a metadata check that throws, or doesn't complete, without findings", async () => {
    const tools = { ...allTools(false), metadataLeak: true };
    metadataMock.mockRejectedValueOnce(new Error("pdf parser crashed"));
    const thrown = await runExtendedTools(TARGET, null, null, [], tools, DB, "owner-1", [], false, [`${TARGET}/a.pdf`]);
    expect((thrown.extended as Record<string, unknown>).metadataLeak).toEqual({ status: "error", note: "Metadata check failed" });

    metadataMock.mockResolvedValueOnce({ status: "error", note: "timeout" });
    const failed = await runExtendedTools(TARGET, null, null, [], tools, DB, "owner-1", [], false, [`${TARGET}/a.pdf`]);
    expect(failed.findings).toEqual([]);
    expect((failed.extended as Record<string, unknown>).metadataLeak).toEqual({ status: "error", note: "timeout" });
  });

  it("does not let subfinder supersede the recon summary when it found nothing", async () => {
    replies.subdomains = { status: "completed", total: 0, subdomains: [], findings: [] };
    replies.httpx = { status: "completed", results: [] };
    const { supersedesReconSubdomains } = await runExtendedTools(TARGET, null, null, [], { ...allTools(false), subdomains: true, httpx: true }, DB, "owner-1");
    expect(supersedesReconSubdomains).toBe(false);
    expect(calls.httpx[0]).toEqual([TARGET, []]);
  });

  it("keeps a CDN-fronted host's zone-transfer findings when port discovery doesn't apply", async () => {
    replies.networkExposure = { status: "not_applicable", host: TARGET, ports: [], findings: [f("zone-transfer.open")] };
    const { findings } = await runExtendedTools(TARGET, null, null, [], { ...allTools(false), networkExposure: true }, DB, "owner-1");
    expect(ids(findings)).toEqual(["zone-transfer.open"]);
  });
});
