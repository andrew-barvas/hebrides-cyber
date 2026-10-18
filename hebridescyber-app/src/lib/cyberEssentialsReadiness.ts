import type { Finding } from "./scanners";

export type CeControl =
  | "Firewalls and internet gateways"
  | "Secure configuration"
  | "User access control"
  | "Malware protection"
  | "Security update management";

export type CeControlAssessment = {
  control: CeControl;
  status: "pass" | "fail" | "partial" | "not-assessed";
  findings: Finding[];
  evidence: string[];
  gaps: string[];
};

export type CeReadinessReport = {
  overall_status: "ready" | "not-ready" | "partial";
  score: number;
  controls: CeControlAssessment[];
  recommendation: string;
};

const CE_CONTROL_CHECKERS: Array<{
  control: CeControl;
  relevantCheckIds: string[];
  assessEvidence: (findings: Finding[]) => { evidence: string[]; gaps: string[] };
}> = [
  {
    control: "Firewalls and internet gateways",
    relevantCheckIds: [
      "ports.open-port",
      "nmap.dangerous-port",
      "whatwaf.no-waf",
      "whatwaf.waf-detected",
      "exposure.sensitive-path",
    ],
    assessEvidence(findings) {
      const evidence: string[] = [];
      const gaps: string[] = [];

      const dangerousPorts = findings.filter((f) => f.checkId?.startsWith("nmap.dangerous-port"));
      const openPorts = findings.filter((f) => f.checkId?.startsWith("ports.open-port"));
      const noWaf = findings.find((f) => f.checkId === "whatwaf.no-waf");
      const hasWaf = findings.find((f) => f.checkId === "whatwaf.waf-detected");

      if (dangerousPorts.length > 0) {
        gaps.push(`${dangerousPorts.length} dangerous port(s) exposed to the internet (database, Docker, etc.)`);
      } else {
        evidence.push("No dangerous ports (databases, Docker) exposed to the internet");
      }

      if (openPorts.length > 5) {
        gaps.push(`${openPorts.length} open ports detected — review whether all are necessary`);
      } else {
        evidence.push(`Only ${openPorts.length || "standard"} port(s) open — minimal attack surface`);
      }

      if (hasWaf) {
        evidence.push("Web Application Firewall detected and active");
      } else if (noWaf) {
        gaps.push("No Web Application Firewall detected — consider adding WAF protection");
      }

      return { evidence, gaps };
    },
  },
  {
    control: "Secure configuration",
    relevantCheckIds: [
      "tls.no-https",
      "tls.weak-protocol",
      "tls.self-signed",
      "tls.hsts-missing",
      "tls.hsts-short",
      "headers.missing-critical",
      "headers.missing-recommended",
      "headers.csp-absent",
      "headers.csp-weak",
      "headers.cors-wildcard",
      "headers.info-disclosure",
      "exposure.sensitive-path",
      "directoryListing.enabled",
      "dns.caa-missing",
    ],
    assessEvidence(findings) {
      const evidence: string[] = [];
      const gaps: string[] = [];

      const noHttps = findings.find((f) => f.checkId === "tls.no-https");
      const weakProto = findings.find((f) => f.checkId === "tls.weak-protocol");
      const selfSigned = findings.find((f) => f.checkId === "tls.self-signed");
      const missingHeaders = findings.find((f) => f.checkId === "headers.missing-critical");
      const noCsp = findings.find((f) => f.checkId === "headers.csp-absent");
      const infoDisc = findings.find((f) => f.checkId === "headers.info-disclosure");
      const exposedPaths = findings.filter((f) => f.checkId?.startsWith("exposure.sensitive-path"));
      const dirListing = findings.filter((f) => f.checkId?.startsWith("directoryListing.enabled"));

      if (noHttps) gaps.push("Site does not use HTTPS — encryption in transit is a CE requirement");
      else evidence.push("HTTPS enabled with valid TLS certificate");

      if (weakProto) gaps.push("Weak TLS protocol version in use (TLS 1.0/1.1)");
      if (selfSigned) gaps.push("Self-signed certificate — not trusted by browsers");

      if (missingHeaders) gaps.push("Critical security headers missing (X-Frame-Options, X-Content-Type-Options, etc.)");
      else evidence.push("Critical security headers present");

      if (noCsp) gaps.push("No Content Security Policy — increases XSS risk");
      else evidence.push("Content Security Policy configured");

      if (infoDisc) gaps.push("Server version information disclosed in headers");
      if (exposedPaths.length > 0) gaps.push(`${exposedPaths.length} sensitive file(s) publicly accessible (.env, .git, etc.)`);
      if (dirListing.length > 0) gaps.push("Directory listing enabled — exposes file structure");

      if (!noHttps && !weakProto && !selfSigned && !missingHeaders) {
        evidence.push("TLS and header configuration meets CE Secure Configuration requirements");
      }

      return { evidence, gaps };
    },
  },
  {
    control: "User access control",
    relevantCheckIds: [
      "headers.cors-wildcard",
      "sessionCheck.no-rate-limit",
      "sessionCheck.session-fixation",
      "sessionCheck.idor-indicator",
      "auth-check.missing-auth-headers",
      "business-logic.missing-csrf",
      "business-logic.no-login-rate-limit",
    ],
    assessEvidence(findings) {
      const evidence: string[] = [];
      const gaps: string[] = [];

      const noRateLimit = findings.filter((f) => f.checkId?.startsWith("sessionCheck.no-rate-limit") || f.checkId?.startsWith("business-logic.no-login-rate-limit"));
      const sessionFixation = findings.filter((f) => f.checkId?.startsWith("sessionCheck.session-fixation"));
      const idor = findings.filter((f) => f.checkId?.startsWith("sessionCheck.idor-indicator"));
      const corsWild = findings.find((f) => f.checkId === "headers.cors-wildcard");
      const missingCsrf = findings.filter((f) => f.checkId?.startsWith("business-logic.missing-csrf"));

      if (noRateLimit.length > 0) gaps.push("No rate limiting on login endpoints — brute-force risk");
      else evidence.push("Login rate limiting in place");

      if (sessionFixation.length > 0) gaps.push("Session fixation vulnerability detected");
      if (idor.length > 0) gaps.push("IDOR indicators detected — potential unauthorised data access");
      if (corsWild) gaps.push("CORS wildcard allows any origin — weakens access control");
      if (missingCsrf.length > 0) gaps.push(`${missingCsrf.length} form(s) missing CSRF protection`);

      if (noRateLimit.length === 0 && sessionFixation.length === 0 && idor.length === 0) {
        evidence.push("No obvious access control weaknesses detected in automated checks");
      }

      return { evidence, gaps };
    },
  },
  {
    control: "Malware protection",
    relevantCheckIds: [
      "safeBrowsing.flagged",
      "exposure.sensitive-path",
    ],
    assessEvidence(findings) {
      const evidence: string[] = [];
      const gaps: string[] = [];

      const safeBrowsingFlagged = findings.find((f) => f.checkId === "safeBrowsing.flagged");

      if (safeBrowsingFlagged) {
        gaps.push("Site flagged by Google Safe Browsing for malware or phishing content");
      } else {
        evidence.push("Not flagged by Google Safe Browsing");
      }

      evidence.push("Note: CE malware protection primarily covers endpoint antivirus — automated web scanning provides limited coverage of this control");

      return { evidence, gaps };
    },
  },
  {
    control: "Security update management",
    // Prefixes of real checkIds. Three entries here used to name ids no
    // check produces ("dockerBaseImage.eol", "trivyImage.cve", and two
    // webapp CMS ids), so end-of-life base images and container CVEs never
    // counted against this control.
    relevantCheckIds: [
      "webapp.vulnerable-js-lib",
      "fingerprint.risky-library",
      "softwareCveDb.",
      "dependency-manifest.",
      "docker-base-image.outdated-base",
      "wpvdb.plugin-vulnerability",
      "wpvdb.theme-vulnerability",
      "trivy-image.vulnerable-package",
      "eol.unsupported",
    ],
    assessEvidence(findings) {
      const evidence: string[] = [];
      const gaps: string[] = [];

      const vulnLibs = findings.filter((f) => f.checkId?.startsWith("webapp.vulnerable-js-lib"));
      const depFindings = findings.filter((f) => f.checkId?.startsWith("dependency-manifest."));
      const wpPlugins = findings.filter((f) => f.checkId?.startsWith("wpvdb.plugin-vulnerability") || f.checkId?.startsWith("wpvdb.theme-vulnerability"));
      const eolImages = findings.filter((f) => f.checkId?.startsWith("docker-base-image.outdated-base"));
      const trivyCves = findings.filter((f) => f.checkId?.startsWith("trivy-image.vulnerable-package"));
      const eolSoftware = findings.filter((f) => f.checkId?.startsWith("eol.unsupported"));
      const outdatedSoftware = findings.filter((f) => f.checkId?.startsWith("fingerprint.risky-library") || f.checkId?.startsWith("softwareCveDb."));

      if (eolSoftware.length > 0) {
        gaps.push(`${eolSoftware.length} piece${eolSoftware.length === 1 ? "" : "s"} of end-of-life software in use — Cyber Essentials requires unsupported software to be removed or upgraded`);
      }
      if (outdatedSoftware.length > 0) gaps.push(`${outdatedSoftware.length} outdated server or CMS component${outdatedSoftware.length === 1 ? "" : "s"} with known vulnerabilities`);

      if (vulnLibs.length > 0) gaps.push(`${vulnLibs.length} client-side JavaScript librar${vulnLibs.length === 1 ? "y" : "ies"} with known vulnerabilities`);
      else evidence.push("No vulnerable JavaScript libraries detected on the frontend");

      if (depFindings.length > 0) gaps.push(`${depFindings.length} server-side dependenc${depFindings.length === 1 ? "y" : "ies"} with known vulnerabilities`);
      if (wpPlugins.length > 0) gaps.push(`${wpPlugins.length} known ${wpPlugins.length === 1 ? "vulnerability" : "vulnerabilities"} in WordPress plugins or themes`);
      if (eolImages.length > 0) gaps.push("Docker base image has reached end-of-life — no longer receiving security updates");
      if (trivyCves.length > 0) gaps.push(`${trivyCves.length} CVE(s) in container image packages`);

      // Only claimed when nothing in this control found a problem.
      if (gaps.length === 0) {
        evidence.push("Software components are up to date with no known vulnerabilities");
      }

      return { evidence, gaps };
    },
  },
];

export function assessCeReadiness(findings: Finding[]): CeReadinessReport {
  const controls: CeControlAssessment[] = CE_CONTROL_CHECKERS.map(({ control, relevantCheckIds, assessEvidence }) => {
    const relevant = findings.filter((f) =>
      f.checkId && relevantCheckIds.some((prefix) => f.checkId!.startsWith(prefix))
    );

    const { evidence, gaps } = assessEvidence(findings);

    const criticalGaps = relevant.filter((f) => f.severity === "critical" || f.severity === "high");
    let status: CeControlAssessment["status"];
    if (relevant.length === 0 && gaps.length === 0) {
      status = evidence.length > 0 ? "pass" : "not-assessed";
    } else if (criticalGaps.length > 0) {
      status = "fail";
    } else if (gaps.length > 0) {
      status = "partial";
    } else {
      status = "pass";
    }

    return { control, status, findings: relevant, evidence, gaps };
  });

  const passCount = controls.filter((c) => c.status === "pass").length;
  const failCount = controls.filter((c) => c.status === "fail").length;
  const score = Math.round((passCount / controls.length) * 100);

  const overall_status: CeReadinessReport["overall_status"] =
    failCount > 0 ? "not-ready" : passCount === controls.length ? "ready" : "partial";

  let recommendation: string;
  if (overall_status === "ready") {
    recommendation = "Your automated assessment indicates readiness for Cyber Essentials self-assessment. This is an automated indicator based on external scanning — the formal certification also covers internal controls (endpoint security, access policies) that require a full self-assessment questionnaire.";
  } else if (overall_status === "partial") {
    recommendation = `${5 - passCount} control${5 - passCount === 1 ? " needs" : "s need"} attention before applying for Cyber Essentials certification. Address the gaps listed below, then re-scan to verify.`;
  } else {
    recommendation = `${failCount} control${failCount === 1 ? "" : "s"} failed with critical issues. Fix these before applying for Cyber Essentials — these would likely cause a certification failure.`;
  }

  return { overall_status, score, controls, recommendation };
}
