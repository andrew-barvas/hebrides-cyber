import { describe, expect, it } from "vitest";
import { classifyQuestion, draftFromEvidence, TOPICS } from "./topics";
import { EMPTY_FACTS, type EvidenceFacts, type SiteEvidence } from "./evidence";
import { NEEDS_YOUR_ANSWER } from "./types";

const site = (over: Partial<SiteEvidence> = {}): SiteEvidence => ({
  host: "acme.co.uk",
  lastScanAt: "2026-11-20T09:00:00Z",
  score: 82,
  evaluated: { tls: true, dns: true, ports: true, hibp: true },
  ...over,
});
const facts = (over: Partial<EvidenceFacts> = {}): EvidenceFacts => ({ ...EMPTY_FACTS, ...over });
const finding = (checkId: string, title = checkId, host = "acme.co.uk", knownExploited = false) => ({ checkId, title, host, knownExploited });
const declared = (questionKey: string, answer: "yes" | "no" | "partial" | "na" = "yes") => ({ questionKey, answer, updatedAt: "2026-11-10T00:00:00Z" });
const devices = (over: Partial<NonNullable<EvidenceFacts["devices"]>> = {}) => ({ total: 4, reporting: 4, passes: 4, atRisk: 0, fails: 0, unsupportedOs: 0, lastSeenAt: "2026-11-25T08:00:00Z", ...over });
const doc = (kind: "cyber_essentials" | "insurance" | "policy" | "penetration_test" | "other", title: string) => ({ kind, title, uploadedAt: "2026-09-01T00:00:00Z", host: "acme.co.uk" });

describe("classifyQuestion", () => {
  it.each([
    ["Is multi-factor authentication enforced for all users?", "mfa"],
    ["Do you use 2FA on email?", "mfa"],
    ["Do your domains publish SPF, DKIM and DMARC records?", "email_auth"],
    ["Is data encrypted in transit?", "encryption"],
    ["Are critical security patches applied within 14 days?", "patching"],
    ["Do you run any end-of-life operating systems?", "supported_software"],
    ["Is anti-virus installed on all endpoints?", "malware"],
    ["Do you have a firewall at the network boundary?", "firewall"],
    ["Is RDP exposed to the internet?", "remote_access"],
    ["Are administrator accounts separate from user accounts?", "admin_accounts"],
    ["Do you prohibit shared accounts?", "unique_accounts"],
    ["Do screens lock automatically after inactivity?", "device_lock"],
    ["Are default passwords changed on all devices?", "secure_config"],
    ["Do you have a password policy?", "passwords"],
    ["Do you carry out regular vulnerability scanning?", "vulnerability_scanning"],
    ["Have you had a penetration test in the last 12 months?", "pen_test"],
    ["Do you hold Cyber Essentials certification?", "certification"],
    ["Do you hold cyber insurance?", "insurance"],
    ["Do you maintain an asset inventory?", "asset_inventory"],
    ["Is your website protected by security headers?", "web_security"],
    ["Have any staff credentials been exposed in a breach?", "breached_credentials"],
    ["Do staff receive security awareness training?", "training"],
    ["Do you have an incident response plan?", "incident_response"],
    ["Have you suffered a ransomware attack in the last 3 years?", "breach_history"],
    ["Are backups encrypted and stored offline?", "backups"],
    ["Do you have a disaster recovery plan?", "continuity"],
    ["Are staff background checked before employment?", "hr"],
    ["Where is customer data stored?", "data_location"],
    ["Are you registered with the ICO and GDPR compliant?", "data_protection"],
    ["How do you assess the security of your third parties?", "third_parties"],
    ["Is there CCTV at your premises?", "physical"],
    ["Do you keep security event logs?", "logging"],
    ["Do you have a documented information security policy?", "policy"],
  ])("%s → %s", (q, topic) => {
    expect(classifyQuestion(q)?.id).toBe(topic);
  });

  it("lets a technical topic beat the supplier topic when the supplier is the respondent", () => {
    expect(classifyQuestion("Does the supplier enforce MFA?")?.id).toBe("mfa");
  });

  it("returns null for a question it has no rule for", () => {
    expect(classifyQuestion("What is your company registration number?")).toBeNull();
  });

  it("has unique topic ids", () => {
    expect(new Set(TOPICS.map((t) => t.id)).size).toBe(TOPICS.length);
  });
});

describe("never invents an answer", () => {
  const rich = facts({ sites: [site()], m365CheckedAt: "2026-11-21T00:00:00Z", devices: devices(), declared: [declared("user-access.mfa")] });
  it.each([
    "Do staff receive security awareness training?",
    "Do you have an incident response plan?",
    "Are backups tested regularly?",
    "Are staff background checked?",
    "Where is customer data stored?",
    "Do you have a business continuity plan?",
    "Is data encrypted at rest on laptops?",
    "What is your company registration number?",
    "Have you had a penetration test?",
    "Do you hold ISO 27001?",
    "Do you hold Cyber Essentials?",
    "Do you have a documented information security policy?",
    "Do you hold cyber insurance?",
  ])("%s → Needs your answer, with no evidence", (q) => {
    const d = draftFromEvidence(q, rich);
    expect(d.status).toBe("needs_answer");
    expect(d.answer).toBe(NEEDS_YOUR_ANSWER);
    expect(d.confidence).toBe("none");
    expect(d.note).toBeTruthy();
  });

  it("with no evidence at all, every technical question needs an answer too", () => {
    for (const q of ["Is MFA enforced?", "Do you have SPF and DMARC?", "Is data encrypted in transit?", "Are patches applied within 14 days?", "Do you run end-of-life software?", "Is RDP exposed?", "Do you have a firewall?", "Are admin accounts separate?", "Is antivirus installed?", "Do you scan for vulnerabilities?", "Is your website secure?", "Do you keep an asset inventory?", "Have credentials been exposed in a breach?", "Do screens lock?", "Do you remove unnecessary software?", "Are default passwords changed?"]) {
      expect(draftFromEvidence(q, EMPTY_FACTS).status, q).toBe("needs_answer");
    }
  });
});

describe("MFA", () => {
  const q = "Is MFA enforced for all users?";
  it("reports a gap from the tenant check, citing the check date", () => {
    const d = draftFromEvidence(q, facts({ m365CheckedAt: "2026-11-21T10:00:00Z", findings: [finding("m365.mfaNotEnforcedAllUsers", "MFA not enforced for all users", "tenant")] }));
    expect(d.answer).toMatch(/^No, not for every account/);
    expect(d.confidence).toBe("high");
    expect(d.evidence[0]).toMatchObject({ source: "m365", date: "2026-11-21" });
  });

  it("reports a Workspace gap", () => {
    const d = draftFromEvidence(q, facts({ workspaceCheckedAt: "2026-11-22T00:00:00Z", findings: [finding("workspace.2svNotEnforced", "2SV not enforced", "tenant")] }));
    expect(d.evidence[0]).toMatchObject({ source: "workspace", date: "2026-11-22" });
  });

  it("says Yes only from a checked tenant", () => {
    const d = draftFromEvidence(q, facts({ m365CheckedAt: "2026-11-21T00:00:00Z", workspaceCheckedAt: "2026-11-20T00:00:00Z" }));
    expect(d.answer).toMatch(/^Yes\. .*Microsoft 365 and Google Workspace/);
    expect(d.evidence).toHaveLength(2);
    expect(draftFromEvidence(q, facts({ workspaceCheckedAt: "2026-11-20T00:00:00Z" })).answer).toMatch(/Google Workspace accounts/);
  });

  it("falls back to the customer's self-assessment at medium confidence", () => {
    const d = draftFromEvidence(q, facts({ declared: [declared("user-access.mfa", "partial")] }));
    expect(d).toMatchObject({ confidence: "medium", status: "draft" });
    expect(d.answer).toMatch(/^Partly\./);
    expect(d.evidence[0]).toMatchObject({ source: "ce_self_assessment", date: "2026-11-10" });
    expect(d.evidence[0].detail).toContain('"Partly"');
  });
});

describe("email authentication", () => {
  const q = "Do you have SPF, DKIM and DMARC?";
  it("reports gaps", () => {
    const d = draftFromEvidence(q, facts({ sites: [site()], findings: [finding("dns.dmarc-missing", "DMARC missing")] }));
    expect(d.answer).toMatch(/^Partly/);
    expect(d.evidence[0]).toMatchObject({ source: "email_auth", date: "2026-11-20" });
  });
  it("ignores MTA-STS findings", () => {
    expect(draftFromEvidence(q, facts({ sites: [site()], findings: [finding("dns.mta-sts-missing")] })).answer).toMatch(/^Yes/);
  });
  it("needs an answer when the DNS check didn't run", () => {
    const d = draftFromEvidence(q, facts({ sites: [site({ evaluated: { tls: true, dns: false, ports: true, hibp: false } })] }));
    expect(d.status).toBe("needs_answer");
    expect(d.note).toMatch(/couldn't check your DNS/);
  });
});

describe("encryption", () => {
  it("answers transit fully, and at rest never", () => {
    const f = facts({ sites: [site(), site({ host: "shop.acme.co.uk" })] });
    const transit = draftFromEvidence("Is data encrypted in transit?", f);
    expect(transit).toMatchObject({ confidence: "high", status: "draft" });
    expect(transit.answer).toMatch(/^Yes, in transit\. acme\.co\.uk, shop\.acme\.co\.uk use HTTPS/);
    const both = draftFromEvidence("Is data encrypted in transit and at rest?", f);
    expect(both.confidence).toBe("low");
    expect(both.answer).toContain("Encryption at rest: needs your answer.");
    expect(draftFromEvidence("Is customer data encrypted?", f).confidence).toBe("low");
  });
  it("reports TLS gaps, and needs an answer when TLS wasn't checked", () => {
    expect(draftFromEvidence("Do you use HTTPS?", facts({ sites: [site()], findings: [finding("tls.weak-protocol", "TLS 1.0 enabled")] })).answer).toMatch(/^Partly/);
    expect(draftFromEvidence("Do you use HTTPS?", facts({ sites: [site({ evaluated: { tls: false, dns: true, ports: true, hibp: true } })] })).status).toBe("needs_answer");
    expect(draftFromEvidence("Do you use HTTPS?", EMPTY_FACTS).note).toMatch(/Scan your website/);
  });
});

describe("patching", () => {
  const q = "Are security patches applied within 14 days?";
  it("reports exploited web vulnerabilities and failing devices", () => {
    const d = draftFromEvidence(q, facts({ sites: [site()], devices: devices({ passes: 3, fails: 1 }), findings: [finding("nuclei.cve:CVE-1", "CVE-1", "acme.co.uk", true), finding("software-cve:x")] }));
    expect(d.answer).toMatch(/^No, not everywhere yet\..*actively exploited.*1 of 4 reporting devices/);
    expect(d.evidence.map((e) => e.source)).toEqual(["scan", "device_agent"]);
  });
  it("reports outdated software without exploitation", () => {
    expect(draftFromEvidence(q, facts({ sites: [site()], findings: [finding("wp-vuln:plugin")] })).answer).toMatch(/outdated software/);
  });
  it("says Yes when every device reports and passes and the scan is clean", () => {
    const d = draftFromEvidence(q, facts({ sites: [site()], devices: devices({ atRisk: 1 }) }));
    expect(d).toMatchObject({ confidence: "high" });
    expect(d.answer).toMatch(/^Yes\. All 4/);
    expect(d.evidence[0].detail).toMatch(/1 close to the limit/);
  });
  it("prefers the self-assessment when the evidence is partial", () => {
    const d = draftFromEvidence(q, facts({ sites: [site()], devices: devices({ total: 6 }), declared: [declared("updates.patch-window")] }));
    expect(d.confidence).toBe("medium");
    expect(d.evidence.map((e) => e.source)).toEqual(["ce_self_assessment", "device_agent", "scan"]);
  });
  it("gives a low-confidence partial answer from devices or the scan alone", () => {
    expect(draftFromEvidence(q, facts({ devices: devices({ reporting: 1, passes: 1 }) }))).toMatchObject({ confidence: "low" });
    const scanOnly = draftFromEvidence(q, facts({ sites: [site()] }));
    expect(scanOnly.confidence).toBe("low");
    expect(scanOnly.answer).toMatch(/internet-facing/);
  });
});

describe("supported software", () => {
  const q = "Do you run any unsupported software?";
  it("reports EOL software and devices", () => {
    const d = draftFromEvidence(q, facts({ devices: devices({ unsupportedOs: 1 }), findings: [finding("eol.unsupported:php", "PHP 7.4 is end of life")] }));
    expect(d.answer).toMatch(/unsupported software on acme\.co\.uk and 1 device running/);
  });
  it("uses the self-assessment, then partial evidence", () => {
    expect(draftFromEvidence(q, facts({ declared: [declared("updates.supported")] })).confidence).toBe("medium");
    expect(draftFromEvidence(q, facts({ devices: devices() })).confidence).toBe("low");
    expect(draftFromEvidence(q, facts({ devices: devices({ unsupportedOs: 2 }) })).answer).toMatch(/2 devices/);
  });
});

describe("remote access and firewalls", () => {
  it("reports exposed services", () => {
    const f = facts({ sites: [site()], findings: [finding("ports.risky-port:3389", "RDP open")] });
    expect(draftFromEvidence("Is RDP open to the internet?", f).answer).toMatch(/^Not fully/);
    expect(draftFromEvidence("Do you have a firewall?", f).answer).toMatch(/^Not fully.*firewall should block/);
  });
  it("evidences closed services, at low confidence for VPN questions", () => {
    const f = facts({ sites: [site()] });
    expect(draftFromEvidence("Are exposed ports closed?", f).confidence).toBe("high");
    expect(draftFromEvidence("Do staff use a VPN for remote access?", f).confidence).toBe("low");
    expect(draftFromEvidence("Is RDP exposed?", facts({ sites: [site({ evaluated: { tls: true, dns: true, ports: false, hibp: true } })] })).status).toBe("needs_answer");
  });
  it("answers firewalls from the self-assessment, choosing the right question", () => {
    const f = facts({ sites: [site()], declared: [declared("firewalls.boundary"), declared("firewalls.host", "no"), declared("firewalls.default-password")] });
    const both = draftFromEvidence("Do you have firewalls in place?", f);
    expect(both.answer).toMatch(/^No\. Not yet in place: a host-based firewall/);
    expect(both.evidence.filter((e) => e.source === "ce_self_assessment")).toHaveLength(2);
    expect(draftFromEvidence("Is a firewall enabled on every laptop?", f).answer).toMatch(/^No\./);
    expect(draftFromEvidence("Have default firewall passwords been changed?", f).answer).toMatch(/^Yes\. The default administrative password/);
    expect(draftFromEvidence("Do you have a firewall?", facts({ sites: [site()] }))).toMatchObject({ confidence: "low", status: "draft" });
  });
});

describe("accounts and configuration", () => {
  it("reports admin gaps from either tenant", () => {
    expect(draftFromEvidence("Are admin accounts limited?", facts({ findings: [finding("m365.tooManyGlobalAdmins", "7 global admins", "tenant")] })).evidence[0].source).toBe("m365");
    expect(draftFromEvidence("Are admin accounts limited?", facts({ findings: [finding("workspace.tooManySuperAdmins", "5 super admins", "tenant")] })).evidence[0].source).toBe("workspace");
  });
  it("answers admin separation from the self-assessment or, weakly, the tenant", () => {
    const tenant = { m365CheckedAt: "2026-11-21T00:00:00Z", workspaceCheckedAt: "2026-11-21T00:00:00Z" };
    expect(draftFromEvidence("Are admin accounts separate?", facts({ ...tenant, declared: [declared("user-access.admin-separation")] })).confidence).toBe("medium");
    expect(draftFromEvidence("Are admin accounts separate?", facts(tenant))).toMatchObject({ confidence: "low" });
  });
  it("answers declared-only topics", () => {
    const f = facts({ declared: [declared("user-access.unique-accounts"), declared("secure-config.device-lock", "na"), declared("secure-config.software-removed"), declared("secure-config.default-accounts", "partial"), declared("malware.protection"), declared("malware.updates", "no")] });
    expect(draftFromEvidence("Do you prohibit shared accounts?", f).answer).toMatch(/^Yes\. Every user/);
    expect(draftFromEvidence("Do screens lock automatically?", f).answer).toBe("Not applicable to our organisation.");
    expect(draftFromEvidence("Is unnecessary software removed?", f).answer).toMatch(/^Yes\./);
    expect(draftFromEvidence("Are default accounts disabled?", f).answer).toMatch(/^Partly\./);
    expect(draftFromEvidence("Describe your secure configuration standard", f).answer).toMatch(/^Partly\..*: yes\./);
    expect(draftFromEvidence("Is anti-malware installed?", f).answer).toMatch(/^Yes\./);
    expect(draftFromEvidence("Is anti-malware kept up to date with signature updates?", f).answer).toMatch(/^No\./);
  });
  it("passwords: default ones from the self-assessment, a policy never", () => {
    const f = facts({ declared: [declared("firewalls.default-password")], sites: [site()], findings: [finding("hibp.domain-breach:x", "3 addresses in breaches")] });
    expect(draftFromEvidence("Are default passwords on routers changed?", f).status).toBe("draft");
    const policy = draftFromEvidence("What are your password requirements?", f);
    expect(policy.status).toBe("needs_answer");
    expect(policy.evidence).toHaveLength(1);
    expect(policy.note).toMatch(/known breaches/);
    expect(draftFromEvidence("Is the default password changed?", EMPTY_FACTS).status).toBe("needs_answer");
    expect(draftFromEvidence("What are your password requirements?", EMPTY_FACTS).evidence).toEqual([]);
  });
});

describe("breached credentials", () => {
  const q = "Have staff credentials been exposed in data breaches?";
  it("reports exposure without claiming any remedy", () => {
    const d = draftFromEvidence(q, facts({ sites: [site()], findings: [finding("hibp.domain-breach:a", "2 addresses in breaches")] }));
    expect(d.answer).toBe("Yes. Addresses on our domain appear in known data breaches: 2 addresses in breaches (acme.co.uk).");
  });
  it("says none were found only when the check ran", () => {
    expect(draftFromEvidence(q, facts({ sites: [site()] })).answer).toMatch(/^No addresses/);
    expect(draftFromEvidence(q, facts({ sites: [site({ evaluated: { tls: true, dns: true, ports: true, hibp: false } })] })).status).toBe("needs_answer");
  });
});

describe("scanning, website and inventory", () => {
  it("evidences vulnerability scanning and cites a published profile", () => {
    const d = draftFromEvidence("Do you carry out vulnerability scanning?", facts({ sites: [site()], profileHosts: ["acme.co.uk"] }));
    expect(d.answer).toMatch(/^Yes\. Our internet-facing systems \(acme\.co\.uk\).*2026-11-20/);
    expect(d.evidence.map((e) => e.source)).toEqual(["scan", "security_profile"]);
    expect(d.evidence[0].detail).toContain("82/100");
    expect(draftFromEvidence("Do you scan for vulnerabilities?", facts({ sites: [site({ score: null })] })).evidence[0].detail).not.toContain("/100");
  });
  it("states the latest website result", () => {
    const d = draftFromEvidence("How do you ensure website security?", facts({ sites: [site()], findings: [finding("headers.csp-missing")] }));
    expect(d.answer).toBe("Our website acme.co.uk was last scanned on 2026-11-20 and scored 82/100, with 1 open finding.");
    expect(draftFromEvidence("Is your website secure?", facts({ sites: [site({ score: null })] })).answer).toMatch(/with 0 open findings/);
  });
  it("evidences a device inventory from the agent, listing sites too", () => {
    const d = draftFromEvidence("Do you maintain an asset inventory?", facts({ devices: devices({ total: 1 }), sites: [site(), site({ host: "a" }), site({ host: "b" }), site({ host: "c" })] }));
    expect(d.answer).toMatch(/^Yes\. We keep an inventory of 1 device,/);
    expect(d.evidence[1].label).toBe("Website scan of acme.co.uk, a, b and 1 more");
    expect(draftFromEvidence("Do you maintain an asset inventory?", facts({ sites: [site()] })).evidence).toHaveLength(1);
  });
});

describe("documents", () => {
  const f = facts({ documents: [doc("cyber_essentials", "CE certificate 2026"), doc("insurance", "Hiscox policy"), doc("policy", "Infosec policy v3"), doc("penetration_test", "Pen test summary"), doc("other", "ISO 27001 certificate")] });
  it.each([
    ["Do you hold Cyber Essentials certification?", "CE certificate 2026"],
    ["Do you hold cyber insurance?", "Hiscox policy"],
    ["Do you have an information security policy?", "Infosec policy v3"],
    ["When was your last penetration test?", "Pen test summary"],
    ["Are you ISO 27001 certified?", "ISO 27001 certificate"],
  ])("%s → cites %s at medium confidence", (q, title) => {
    const d = draftFromEvidence(q, f);
    expect(d).toMatchObject({ status: "draft", confidence: "medium" });
    expect(d.answer).toContain(title);
    expect(d.evidence[0]).toMatchObject({ source: "document", date: "2026-09-01" });
  });
});

describe("documented-policy questions", () => {
  it("lowers confidence when evidence shows practice but the question asks for a policy, citing any policy document", () => {
    const d = draftFromEvidence("Is MFA enforced by policy for all staff?", facts({ m365CheckedAt: "2026-11-21T00:00:00Z", documents: [doc("policy", "Access policy")] }));
    expect(d.confidence).toBe("low");
    expect(d.note).toMatch(/documented policy/);
    expect(d.evidence.map((e) => e.source)).toEqual(["m365", "document"]);
  });
});
