// Rule-first drafting: which topic a questionnaire question is about, and
// what the customer's own evidence says about it. Works with no AI at all;
// aiWording.ts only rephrases what this produces.
//
// The rules that keep it honest:
//   - a "Yes" needs evidence that the check actually ran (SiteEvidence's
//     `evaluated`, a tenant check date, a reporting device). No findings from
//     a check that didn't run is not evidence (CLAUDE.md rule 7);
//   - what we can't see (policies, training, HR, backups, data location) is
//     "Needs your answer" unless the customer has given us something that
//     answers it, such as an uploaded document;
//   - the customer's own self-assessment answers are cited as theirs, at
//     medium confidence, never as something we checked.
import { CE_QUESTIONS, type CeAnswerValue } from "../ceSelfAssessment";
import { KIND_LABELS, type DocumentKind } from "../trustDocumentKinds";
import type { DeclaredAnswer, EvidenceFacts, EvidenceFinding, SiteEvidence } from "./evidence";
import { NEEDS_YOUR_ANSWER, type Confidence, type DraftAnswer, type EvidenceCitation } from "./types";

type Ctx = { question: string; facts: EvidenceFacts };
type Resolved = Omit<DraftAnswer, "topic" | "reusedFrom">;

export type Topic = {
  id: string;
  label: string;
  patterns: RegExp[];
  resolve: (ctx: Ctx) => Resolved;
};

// ---------------------------------------------------------------- helpers

const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : null);
const hostList = (hosts: string[]) => (hosts.length <= 3 ? hosts.join(", ") : `${hosts.slice(0, 3).join(", ")} and ${hosts.length - 3} more`);
const titlesOf = (rows: EvidenceFinding[]) => [...new Set(rows.map((r) => `${r.title} (${r.host})`))].slice(0, 5);
const matching = (facts: EvidenceFacts, re: RegExp) => facts.findings.filter((f) => re.test(f.checkId));
const newest = (sites: SiteEvidence[]) => sites.reduce<string | null>((d, s) => (!d || s.lastScanAt > d ? s.lastScanAt : d), null);

function needsAnswer(note: string, evidence: EvidenceCitation[] = []): Resolved {
  return { answer: NEEDS_YOUR_ANSWER, evidence, confidence: "none", status: "needs_answer", note };
}

function draft(answer: string, confidence: Confidence, evidence: EvidenceCitation[], note: string | null = null): Resolved {
  return { answer, evidence, confidence, status: "draft", note };
}

function scanCite(sites: SiteEvidence[], detail: string): EvidenceCitation {
  return { source: "scan", label: `Website scan of ${hostList(sites.map((s) => s.host))}`, detail, date: day(newest(sites)) };
}

function gapCite(facts: EvidenceFacts, rows: EvidenceFinding[], source: EvidenceCitation["source"] = "scan"): EvidenceCitation {
  const hosts = [...new Set(rows.map((r) => r.host))];
  const sites = facts.sites.filter((s) => hosts.includes(s.host));
  const label =
    source === "m365" ? "Microsoft 365 check" : source === "workspace" ? "Google Workspace check" : source === "email_auth" ? `Email authentication check of ${hostList(hosts)}` : `Website scan of ${hostList(hosts)}`;
  const date = source === "m365" ? day(facts.m365CheckedAt) : source === "workspace" ? day(facts.workspaceCheckedAt) : day(newest(sites));
  return { source, label, detail: `Open findings: ${titlesOf(rows).join("; ")}`, date };
}

const CE_PROMPTS = new Map(CE_QUESTIONS.map((q) => [q.key, q.prompt]));
const DECLARED_WORD: Record<CeAnswerValue, string> = { yes: "Yes", no: "No", partial: "Partly", na: "Not applicable" };

/** What each self-assessment question confirms, for wording a declared answer. */
const PRACTICE: Record<string, string> = {
  "firewalls.boundary": "a correctly configured firewall protects the boundary of every network in scope",
  "firewalls.host": "a host-based firewall is enabled on every in-scope device",
  "firewalls.default-password": "the default administrative password on every firewall and router has been changed to a strong, unique one",
  "secure-config.default-accounts": "default and unnecessary accounts are removed or disabled, and default passwords changed, on every device and service",
  "secure-config.software-removed": "unused software, unnecessary services and auto-run features are removed or disabled on in-scope devices",
  "secure-config.device-lock": "every device needs a PIN, password or biometric to unlock, with brute-force protection",
  "user-access.unique-accounts": "every user has their own named account, created through an approved process",
  "user-access.admin-separation": "administrator rights are limited to those who need them, used from separate admin accounts and reviewed",
  "user-access.mfa": "multi-factor authentication is enabled on all cloud services and for administrative access where available",
  "malware.protection": "anti-malware software or application allow-listing is active on every in-scope device",
  "malware.updates": "malware protection updates automatically and scans files on access",
  "updates.supported": "all software on in-scope devices is licensed and supported by its vendor",
  "updates.patch-window": "critical and high-risk security updates are applied within 14 days of release",
};

const capitalise = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function declaredText(a: DeclaredAnswer): string {
  const practice = PRACTICE[a.questionKey] ?? "this is in place";
  if (a.answer === "yes") return `Yes. ${capitalise(practice)}.`;
  if (a.answer === "partial") return `Partly. Not yet everywhere: ${practice}.`;
  if (a.answer === "no") return `No. Not yet in place: ${practice}.`;
  return "Not applicable to our organisation.";
}

function declaredCite(a: DeclaredAnswer): EvidenceCitation {
  return {
    source: "ce_self_assessment",
    label: "Your Cyber Essentials self-assessment",
    detail: `You answered "${DECLARED_WORD[a.answer]}" to: ${CE_PROMPTS.get(a.questionKey) ?? a.questionKey}`,
    date: day(a.updatedAt),
  };
}

const declaredOf = (facts: EvidenceFacts, key: string) => facts.declared.find((d) => d.questionKey === key) ?? null;

/** The customer's self-assessment answers to `keys`, as a medium-confidence draft, or null. */
function fromDeclared(facts: EvidenceFacts, keys: string[], extra: EvidenceCitation[] = []): Resolved | null {
  const found = keys.map((k) => declaredOf(facts, k)).filter((a): a is DeclaredAnswer => a !== null);
  if (!found.length) return null;
  // The weakest answer leads: one "No" among several "Yes" means "No".
  const order: CeAnswerValue[] = ["no", "partial", "yes", "na"];
  found.sort((a, b) => order.indexOf(a.answer) - order.indexOf(b.answer));
  const text = found.length === 1 ? declaredText(found[0]) : `${declaredText(found[0])}${found.slice(1).map((a) => ` ${capitalise(PRACTICE[a.questionKey] ?? "")}: ${DECLARED_WORD[a.answer].toLowerCase()}.`).join("")}`;
  return draft(text, "medium", [...found.map(declaredCite), ...extra], "From your own self-assessment answers. Hebrides Cyber hasn't checked this.");
}

function docsOf(facts: EvidenceFacts, kind: DocumentKind, titleTest?: RegExp): EvidenceCitation[] {
  return facts.documents
    .filter((d) => d.kind === kind && (!titleTest || titleTest.test(d.title)))
    .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt))
    .slice(0, 3)
    .map((d) => ({ source: "document", label: `${KIND_LABELS[d.kind]}: ${d.title}`, detail: `Uploaded to your security profile for ${d.host}.`, date: day(d.uploadedAt) }));
}

function fromDocument(facts: EvidenceFacts, kind: DocumentKind, answer: (title: string) => string, missing: string, titleTest?: RegExp): Resolved {
  const docs = docsOf(facts, kind, titleTest);
  if (!docs.length) return needsAnswer(missing);
  const title = facts.documents.find((d) => d.kind === kind && (!titleTest || titleTest.test(d.title)))!.title;
  return draft(answer(title), "medium", docs, "Based on a document you uploaded. Check it is current and covers what the question asks.");
}

// ---------------------------------------------------------------- resolvers

const MFA_GAP = /^m365\.(mfaNotEnforced|mfa-off|legacyAuthAllowed|weakMfaMethodsEnabled)|^workspace\.(2svNotEnforced|2sv-off|adminsWithout2sv)/;

function mfa({ facts }: Ctx): Resolved {
  const m365Gaps = matching(facts, /^m365\./).filter((f) => MFA_GAP.test(f.checkId));
  const wsGaps = matching(facts, /^workspace\./).filter((f) => MFA_GAP.test(f.checkId));
  if (m365Gaps.length || wsGaps.length) {
    const cites = [...(m365Gaps.length ? [gapCite(facts, m365Gaps, "m365")] : []), ...(wsGaps.length ? [gapCite(facts, wsGaps, "workspace")] : [])];
    return draft(`No, not for every account. Our checks found: ${titlesOf([...m365Gaps, ...wsGaps]).join("; ")}.`, "high", cites);
  }
  const checked: EvidenceCitation[] = [];
  if (facts.m365CheckedAt) checked.push({ source: "m365", label: "Microsoft 365 check", detail: "No accounts without multi-factor authentication were found.", date: day(facts.m365CheckedAt) });
  if (facts.workspaceCheckedAt) checked.push({ source: "workspace", label: "Google Workspace check", detail: "No accounts without 2-step verification were found.", date: day(facts.workspaceCheckedAt) });
  if (checked.length) {
    const where = facts.m365CheckedAt && facts.workspaceCheckedAt ? "Microsoft 365 and Google Workspace" : facts.m365CheckedAt ? "Microsoft 365" : "Google Workspace";
    return draft(`Yes. Multi-factor authentication is in place for our ${where} accounts; a check of the tenant found no accounts without it.`, "high", checked);
  }
  return fromDeclared(facts, ["user-access.mfa"]) ?? needsAnswer("Connect Microsoft 365 or Google Workspace in Integrations to have MFA checked, or answer it yourself.");
}

const EMAIL_GAP = /^dns\.(spf|dmarc|dkim)/;

function emailAuth({ facts }: Ctx): Resolved {
  const gaps = matching(facts, /^dns\./).filter((f) => EMAIL_GAP.test(f.checkId));
  if (gaps.length) return draft(`Partly. Our latest checks found: ${titlesOf(gaps).join("; ")}.`, "high", [gapCite(facts, gaps, "email_auth")]);
  const checked = facts.sites.filter((s) => s.evaluated.dns);
  if (checked.length) {
    return draft(
      `Yes. SPF, DKIM and DMARC are in place on ${hostList(checked.map((s) => s.host))}; our latest check found no missing or misconfigured records.`,
      "high",
      [{ source: "email_auth", label: `Email authentication check of ${hostList(checked.map((s) => s.host))}`, detail: "No missing or misconfigured SPF, DKIM or DMARC records.", date: day(newest(checked)) }],
    );
  }
  return needsAnswer(facts.sites.length ? "The latest scan couldn't check your DNS records. Run a new scan, or answer it yourself." : "Scan your domain to have SPF, DKIM and DMARC checked.");
}

const TLS_GAP = /^tls\.(no-https|cert-expired|cert-untrusted|self-signed|weak-protocol|weak-cipher|hsts)/;

function encryption({ question, facts }: Ctx): Resolved {
  const explicitRest = /at rest|stored data|disk|full[- ]disk|bitlocker|filevault|database|laptops?|devices?/i.test(question);
  const explicitTransit = /in transit|https|\btls\b|\bssl\b|certificate|website|web site|transmi/i.test(question);
  if (explicitRest && !explicitTransit) return needsAnswer("Encryption at rest (disks, databases, backups) can't be seen from outside, so it needs your answer.");
  // Only a question plainly about transit is fully answered; otherwise at-rest is still open.
  const asksRest = !explicitTransit || explicitRest;
  const gaps = matching(facts, /^tls\./).filter((f) => TLS_GAP.test(f.checkId));
  const rest = asksRest ? " Encryption at rest: needs your answer." : "";
  const restNote = asksRest ? "The evidence covers encryption in transit only. Add how stored data is encrypted before accepting." : null;
  if (gaps.length) return draft(`Partly. Data in transit to our websites is encrypted, but our latest scan found: ${titlesOf(gaps).join("; ")}.${rest}`, "high", [gapCite(facts, gaps)], restNote);
  const checked = facts.sites.filter((s) => s.evaluated.tls);
  if (checked.length) {
    return draft(
      `Yes, in transit. ${hostList(checked.map((s) => s.host))} ${checked.length === 1 ? "uses" : "use"} HTTPS with valid certificates and no weak protocols.${rest}`,
      asksRest ? "low" : "high",
      [scanCite(checked, "HTTPS with a valid certificate; no weak TLS protocols or ciphers found.")],
      restNote,
    );
  }
  return needsAnswer(facts.sites.length ? "The latest scan couldn't check your TLS set-up. Run a new scan, or answer it yourself." : "Scan your website to have encryption in transit checked.");
}

const PATCH_GAP = /^eol\.unsupported|^network-exposure\.service-(cve|eol)|^nuclei\.cve|^software-cve|^wp-vuln/;

function deviceCite(facts: EvidenceFacts, detail: string): EvidenceCitation {
  return { source: "device_agent", label: `Device agent (${facts.devices!.reporting} of ${facts.devices!.total} devices reporting)`, detail, date: day(facts.devices!.lastSeenAt) };
}

function patching({ facts }: Ctx): Resolved {
  const web = matching(facts, PATCH_GAP);
  const exploited = web.filter((r) => r.knownExploited);
  const dev = facts.devices && facts.devices.reporting ? facts.devices : null;
  const problems: string[] = [];
  const cites: EvidenceCitation[] = [];
  if (web.length) {
    problems.push(exploited.length ? `actively exploited vulnerabilities on ${hostList([...new Set(exploited.map((r) => r.host))])}` : `outdated software on ${hostList([...new Set(web.map((r) => r.host))])}`);
    cites.push(gapCite(facts, exploited.length ? exploited : web));
  }
  if (dev && dev.fails) {
    problems.push(`${dev.fails} of ${dev.reporting} reporting devices with high-risk updates outstanding for more than 14 days`);
    cites.push(deviceCite(facts, `${dev.fails} device(s) fail the 14-day patch rule.`));
  }
  if (problems.length) return draft(`No, not everywhere yet. Our latest checks found ${problems.join(" and ")}.`, "high", cites);

  const scanned = facts.sites.length > 0;
  if (dev) cites.push(deviceCite(facts, `All ${dev.reporting} reporting devices meet the 14-day rule${dev.atRisk ? ` (${dev.atRisk} close to the limit)` : ""}.`));
  if (scanned) cites.push(scanCite(facts.sites, "No known-vulnerable or unsupported software found on internet-facing systems."));
  if (dev && scanned && dev.reporting === dev.total) {
    return draft(`Yes. All ${dev.reporting} of our enrolled devices apply high-risk security updates within 14 days, and our internet-facing systems show no known-vulnerable software.`, "high", cites);
  }
  const declared = fromDeclared(facts, ["updates.patch-window"], cites);
  if (declared) return declared;
  if (dev || scanned) {
    const what = dev ? `${dev.reporting} enrolled device${dev.reporting === 1 ? "" : "s"}` : "our internet-facing systems";
    return draft(
      `Yes, on ${what}: ${dev ? "every reporting device meets the 14-day rule" : "no known-vulnerable or unsupported software was found"}.`,
      "low",
      cites,
      "The evidence doesn't cover every device. Confirm the rest before accepting, or enrol them in the device agent.",
    );
  }
  return needsAnswer("Install the device agent or answer the Cyber Essentials self-assessment to have patching evidenced.");
}

function supportedSoftware({ facts }: Ctx): Resolved {
  const eol = matching(facts, /^eol\.unsupported|^network-exposure\.service-eol/);
  const dev = facts.devices && facts.devices.reporting ? facts.devices : null;
  const cites: EvidenceCitation[] = [];
  const problems: string[] = [];
  if (eol.length) {
    problems.push(`unsupported software on ${hostList([...new Set(eol.map((r) => r.host))])}`);
    cites.push(gapCite(facts, eol));
  }
  if (dev && dev.unsupportedOs) {
    problems.push(`${dev.unsupportedOs} device${dev.unsupportedOs === 1 ? "" : "s"} running an operating system past its end of life`);
    cites.push(deviceCite(facts, `${dev.unsupportedOs} device(s) on an unsupported operating system.`));
  }
  if (problems.length) return draft(`No, not everywhere. Our checks found ${problems.join(" and ")}.`, "high", cites);
  if (dev) cites.push(deviceCite(facts, "No reporting device runs an operating system past its end of life."));
  if (facts.sites.length) cites.push(scanCite(facts.sites, "No end-of-life software found on internet-facing systems."));
  const declared = fromDeclared(facts, ["updates.supported"], cites);
  if (declared) return declared;
  if (cites.length) return draft("Yes, as far as our checks can see: no unsupported software was found.", "low", cites, "Our checks see internet-facing systems and enrolled devices only. Confirm the rest before accepting.");
  return needsAnswer("Install the device agent or answer the Cyber Essentials self-assessment to have this evidenced.");
}

const REMOTE_GAP = /^ports\.risky-port|^network-exposure\.open-port:(21|22|23|445|1433|3306|3389|5432|5900|5985|5986)\b/;

function remoteAccess({ question, facts }: Ctx): Resolved {
  const gaps = matching(facts, REMOTE_GAP);
  if (gaps.length) return draft(`Not fully. Our latest scan found remote access services open to the internet: ${titlesOf(gaps).join("; ")}.`, "high", [gapCite(facts, gaps)]);
  const checked = facts.sites.filter((s) => s.evaluated.ports);
  if (checked.length) {
    return draft(
      "No remote access services (such as RDP, SSH, VNC or file sharing) are open to the internet on our scanned systems.",
      // A question about how staff connect (VPN, MFA) is only partly answered by what is closed.
      /vpn|how .*connect|multi[- ]?factor|\bmfa\b/i.test(question) ? "low" : "high",
      [scanCite(checked, "No remote access or file-sharing services found open to the internet.")],
      "This covers what is visible from the internet. Add how staff connect remotely (VPN, MFA) if the question asks.",
    );
  }
  return needsAnswer("The latest scan didn't check open ports. Run a new scan, or answer it yourself.");
}

function firewall(ctx: Ctx): Resolved {
  const { question, facts } = ctx;
  const keys = /host|device|laptop|software firewall|endpoint/i.test(question) ? ["firewalls.host"] : /default|password/i.test(question) ? ["firewalls.default-password"] : ["firewalls.boundary", "firewalls.host"];
  const exposed = matching(facts, REMOTE_GAP);
  const checked = facts.sites.filter((s) => s.evaluated.ports);
  const extra = exposed.length ? [gapCite(facts, exposed)] : checked.length ? [scanCite(checked, "No remote access or file-sharing services found open to the internet.")] : [];
  if (exposed.length) return draft(`Not fully. Our latest scan found services open to the internet that a firewall should block: ${titlesOf(exposed).join("; ")}.`, "high", extra);
  const declared = fromDeclared(facts, keys, extra);
  if (declared) return declared;
  if (checked.length) {
    return draft(
      "Our external scan found no remote access or file-sharing services open to the internet.",
      "low",
      extra,
      "This supports a firewall answer but doesn't prove one. Describe your firewalls before accepting.",
    );
  }
  return needsAnswer("Answer the firewall questions in the Cyber Essentials self-assessment, or answer it yourself.");
}

const ADMIN_GAP = /^m365\.(tooManyGlobalAdmins|singleGlobalAdmin|syncedGlobalAdmin|mfaNotEnforcedAdmins)|^workspace\.(tooManySuperAdmins|singleSuperAdmin|adminsWithout2sv)/;

function adminAccounts({ facts }: Ctx): Resolved {
  const gaps = matching(facts, ADMIN_GAP);
  if (gaps.length) {
    const src = gaps.every((g) => g.checkId.startsWith("workspace.")) ? "workspace" : "m365";
    return draft(`Partly. Our tenant check found: ${titlesOf(gaps).join("; ")}.`, "high", [gapCite(facts, gaps, src)]);
  }
  const tenant: EvidenceCitation[] = [];
  if (facts.m365CheckedAt) tenant.push({ source: "m365", label: "Microsoft 365 check", detail: "Global admin count and admin MFA within recommended limits.", date: day(facts.m365CheckedAt) });
  if (facts.workspaceCheckedAt) tenant.push({ source: "workspace", label: "Google Workspace check", detail: "Super admin count and admin 2-step verification within recommended limits.", date: day(facts.workspaceCheckedAt) });
  return fromDeclared(facts, ["user-access.admin-separation"], tenant) ?? (tenant.length
    ? draft("Administrator accounts in our cloud tenant are limited in number and protected with multi-factor authentication.", "low", tenant, "The tenant check doesn't show whether admins use separate accounts. Confirm before accepting.")
    : needsAnswer("Answer the admin-access question in the Cyber Essentials self-assessment, or answer it yourself."));
}

function malware({ question, facts }: Ctx): Resolved {
  const keys = /updat|signature|definition/i.test(question) ? ["malware.protection", "malware.updates"] : ["malware.protection"];
  return fromDeclared(facts, keys) ?? needsAnswer("Anti-malware on devices can't be seen from outside. Answer the Cyber Essentials self-assessment, or answer it yourself.");
}

function declaredOnly(keys: string[], missing: string) {
  return ({ facts }: Ctx): Resolved => fromDeclared(facts, keys) ?? needsAnswer(missing);
}

function secureConfig({ question, facts }: Ctx): Resolved {
  const keys = /default/i.test(question)
    ? /router|firewall/i.test(question)
      ? ["firewalls.default-password"]
      : ["secure-config.default-accounts", "firewalls.default-password"]
    : /software|service|auto-?run|auto-?play/i.test(question)
      ? ["secure-config.software-removed"]
      : ["secure-config.default-accounts", "secure-config.software-removed"];
  return fromDeclared(facts, keys) ?? needsAnswer("Answer the secure-configuration questions in the Cyber Essentials self-assessment, or answer it yourself.");
}

function passwords({ question, facts }: Ctx): Resolved {
  if (/default/i.test(question)) return fromDeclared(facts, ["firewalls.default-password", "secure-config.default-accounts"]) ?? needsAnswer("Answer it yourself.");
  const leaked = matching(facts, /^hibp\.domain-breach/);
  const evidence = leaked.length ? [gapCite(facts, leaked)] : [];
  return needsAnswer("A password policy can't be seen from outside, so it needs your answer." + (leaked.length ? " Note: addresses on your domain appear in known breaches." : ""), evidence);
}

function breachedCredentials({ facts }: Ctx): Resolved {
  const leaked = matching(facts, /^hibp\.domain-breach/);
  if (leaked.length) return draft(`Yes. Addresses on our domain appear in known data breaches: ${titlesOf(leaked).join("; ")}.`, "high", [gapCite(facts, leaked)], "Add what you have done about it (password resets, MFA) before accepting.");
  const checked = facts.sites.filter((s) => s.evaluated.hibp);
  if (checked.length) return draft(`No addresses on ${hostList(checked.map((s) => s.host))} were found in known data breaches when last checked.`, "high", [scanCite(checked, "No addresses found in known breach data.")]);
  return needsAnswer("Breach exposure hasn't been checked for your domain yet. Answer it yourself.");
}

function scanning({ facts }: Ctx): Resolved {
  if (!facts.sites.length) return needsAnswer("No completed scan yet. Scan your website to evidence this.");
  const cites = [scanCite(facts.sites, `External vulnerability scan by Hebrides Cyber.${facts.sites[0].score !== null ? ` Latest security score ${facts.sites[0].score}/100 for ${facts.sites[0].host}.` : ""}`)];
  for (const host of facts.profileHosts.filter((h) => facts.sites.some((s) => s.host === h)).slice(0, 2)) {
    cites.push({ source: "security_profile", label: `Public security profile for ${host}`, detail: "Published, showing the latest scan result.", date: null });
  }
  return draft(`Yes. Our internet-facing systems (${hostList(facts.sites.map((s) => s.host))}) are scanned for vulnerabilities by Hebrides Cyber; the latest scan was on ${day(newest(facts.sites))}.`, "high", cites);
}

function webSecurity(ctx: Ctx): Resolved {
  const { facts } = ctx;
  if (!facts.sites.length) return needsAnswer("No completed scan yet. Scan your website to evidence this.");
  const s = facts.sites[0];
  const open = facts.findings.filter((f) => f.host === s.host).length;
  const res = scanning(ctx);
  return draft(
    `Our website ${s.host} was last scanned on ${day(s.lastScanAt)}${s.score !== null ? ` and scored ${s.score}/100` : ""}, with ${open} open finding${open === 1 ? "" : "s"}.`,
    "high",
    res.evidence,
    "States the latest scan result. Add anything the question asks beyond it (a web application firewall, code review).",
  );
}

function assetInventory({ facts }: Ctx): Resolved {
  const cites: EvidenceCitation[] = [];
  if (facts.devices) cites.push(deviceCite(facts, `${facts.devices.total} device(s) enrolled, reporting operating system and installed software.`));
  if (facts.sites.length) cites.push(scanCite(facts.sites, `${facts.sites.length} internet-facing site(s) tracked.`));
  if (!facts.devices) return needsAnswer("Enrol your devices in the device agent to evidence a device inventory, or answer it yourself.", cites);
  return draft(
    `Yes. We keep an inventory of ${facts.devices.total} device${facts.devices.total === 1 ? "" : "s"}, each reporting its operating system and installed software automatically.`,
    "medium",
    cites,
    "Covers enrolled devices only. Check the count matches all your devices before accepting.",
  );
}

// ---------------------------------------------------------------- topics

const orgOnly = (what: string) => () => needsAnswer(`${what} can't be seen from outside your organisation, so it needs your answer.`);

/**
 * Ordered: on a tie in matched patterns the earlier topic wins, so the
 * organisational topics (which always need the customer's answer) come
 * first. "Are backups encrypted?" is a backup question, not an encryption one.
 */
export const TOPICS: readonly Topic[] = [
  { id: "breach_history", label: "Past incidents", patterns: [/(suffered|experienced|had|been (the )?(victim|subject))\b.*\b(breach|incident|attack|ransomware|claim)/i], resolve: orgOnly("Your incident history") },
  { id: "training", label: "Staff training", patterns: [/\btrain(ing|ed)?\b/i, /awareness/i, /phishing (simulation|test|exercise)/i], resolve: orgOnly("Staff training") },
  { id: "incident_response", label: "Incident response", patterns: [/incident/i, /breach (response|notification|plan|procedure)/i, /respond to .*(incident|breach|attack)/i], resolve: orgOnly("An incident response plan") },
  { id: "backups", label: "Backups", patterns: [/back-?ups?\b/i, /back up/i, /\brestore\b/i, /recovery point/i], resolve: orgOnly("Backups") },
  { id: "continuity", label: "Business continuity", patterns: [/business continuity/i, /disaster recovery/i, /\bbcp\b/i, /continuity/i], resolve: orgOnly("Business continuity planning") },
  { id: "hr", label: "People and HR", patterns: [/background check/i, /vetting/i, /screening/i, /pre-employment/i, /confidentiality agreement/i, /\bnda\b/i, /leavers?\b/i, /joiners?\b/i, /on-?boarding/i, /off-?boarding/i, /disciplinary/i, /employment contract/i], resolve: orgOnly("HR processes") },
  { id: "data_location", label: "Data location", patterns: [/data (is |are )?(stored|hosted|located|resid|held)/i, /data residency/i, /where (is|are)\b.*\b(data|stored|hosted)/i, /outside (of )?the (uk|eea|eu)/i, /international transfer/i, /data cent(re|er)/i], resolve: orgOnly("Where your data is stored") },
  { id: "data_protection", label: "Data protection", patterns: [/gdpr/i, /data protection/i, /\bdpo\b/i, /privacy (policy|notice)/i, /personal data/i, /retention/i, /\bico\b/i, /subject access/i], resolve: orgOnly("Data protection arrangements") },
  { id: "physical", label: "Physical security", patterns: [/physical/i, /premises/i, /\bcctv\b/i, /visitors?\b/i, /clean desk/i], resolve: orgOnly("Physical security") },
  { id: "logging", label: "Logging and monitoring", patterns: [/\blogging\b/i, /\blogs\b/i, /(event|audit|security) logs?\b/i, /\bsiem\b/i, /audit trail/i, /monitor(ing|ed)? .*(event|activity|access|system|network)/i], resolve: orgOnly("Internal logging and monitoring") },
  { id: "pen_test", label: "Penetration testing", patterns: [/penetration test/i, /pen[- ]?test/i, /ethical hack/i, /red team/i], resolve: ({ facts }) => fromDocument(facts, "penetration_test", (t) => `Yes. Our most recent penetration test summary is available on request (${t}).`, "No penetration test report is on file. Automated scanning isn't a penetration test, so this needs your answer.") },
  { id: "insurance", label: "Cyber insurance", patterns: [/insurance/i, /insured/i], resolve: ({ facts }) => fromDocument(facts, "insurance", (t) => `Yes. We hold cyber insurance; the certificate is available on request (${t}).`, "No insurance certificate is on file. Answer it yourself, or upload the certificate to your security profile.") },
  { id: "certification", label: "Certification", patterns: [/cyber essentials/i, /iso ?27001/i, /\bsoc ?2\b/i, /certif(ied|ication|icate)/i, /accredit/i], resolve: ({ question, facts }) =>
      /iso|27001|soc ?2/i.test(question)
        ? fromDocument(facts, "other", (t) => `Yes. Our certificate is available on request (${t}).`, "No certificate for this standard is on file, so it needs your answer.", /27001|iso|soc ?2/i)
        : fromDocument(facts, "cyber_essentials", (t) => `Yes. We hold Cyber Essentials certification; the certificate is available on request (${t}).`, "No Cyber Essentials certificate is on file. Hebrides Cyber's readiness view isn't certification, so this needs your answer.") },
  { id: "policy", label: "Security policy", patterns: [/information security polic/i, /security polic(y|ies)/i, /(written|documented|formal) (security )?polic/i, /acceptable use/i], resolve: ({ facts }) => fromDocument(facts, "policy", (t) => `Yes. Our security policy is documented and available on request (${t}).`, "No security policy document is on file, so this needs your answer.") },
  { id: "mfa", label: "Multi-factor authentication", patterns: [/multi[- ]?factor/i, /\bmfa\b/i, /\b2fa\b/i, /two[- ](factor|step)/i, /2-step/i, /\b2sv\b/i], resolve: mfa },
  { id: "email_auth", label: "Email security", patterns: [/\bspf\b/i, /\bdkim\b/i, /\bdmarc\b/i, /spoof/i, /email authentication/i, /email security/i], resolve: emailAuth },
  { id: "breached_credentials", label: "Breached credentials", patterns: [/credentials?\b.*\b(breach|leak|expos|compromis)/i, /(breach|leak)\w*\b.*\b(credential|password)/i, /have i been pwned/i], resolve: breachedCredentials },
  { id: "encryption", label: "Encryption", patterns: [/encrypt/i, /\btls\b/i, /\bssl\b/i, /https/i, /in transit/i, /at rest/i], resolve: encryption },
  { id: "supported_software", label: "Supported software", patterns: [/end[- ]of[- ]life/i, /unsupported/i, /supported (software|versions?|operating)/i, /out of support/i, /\beol\b/i, /legacy (software|systems?)/i], resolve: supportedSoftware },
  { id: "patching", label: "Patching", patterns: [/patch/i, /security updates?/i, /software updates?/i, /updates? (are )?(applied|installed)/i, /14 days/i, /vulnerabilit(y|ies) (are )?(remediat|fix|resolv)/i], resolve: patching },
  { id: "malware", label: "Anti-malware", patterns: [/anti-?virus/i, /anti-?malware/i, /malware/i, /endpoint (protection|detection|security)/i, /\bedr\b/i, /\bxdr\b/i], resolve: malware },
  { id: "remote_access", label: "Remote access", patterns: [/remote access/i, /\brdp\b/i, /\bvpn\b/i, /\bssh\b/i, /remote desktop/i, /open ports?/i, /exposed (services|ports)/i], resolve: remoteAccess },
  { id: "firewall", label: "Firewalls", patterns: [/firewall/i, /internet gateway/i, /boundary/i], resolve: firewall },
  { id: "admin_accounts", label: "Admin accounts", patterns: [/admin(istrat(or|ive))?\b.*\b(accounts?|rights|privileges?|access)/i, /privileged (access|accounts?|users?)/i, /least privilege/i, /super ?admin/i, /global admin/i], resolve: adminAccounts },
  { id: "unique_accounts", label: "User accounts", patterns: [/shared accounts?/i, /(unique|individual|named|generic) (user )?(accounts?|ids?|log-?ins?)/i], resolve: declaredOnly(["user-access.unique-accounts"], "Answer the user-accounts question in the Cyber Essentials self-assessment, or answer it yourself.") },
  { id: "device_lock", label: "Device locking", patterns: [/screen ?lock/i, /device lock/i, /lock(ed|s)? (after|when|automatically)/i, /\bpin\b/i, /biometric/i], resolve: declaredOnly(["secure-config.device-lock"], "Answer the device-lock question in the Cyber Essentials self-assessment, or answer it yourself.") },
  { id: "secure_config", label: "Secure configuration", patterns: [/secure configuration/i, /harden/i, /default (settings|configuration|accounts?|passwords?)/i, /unnecessary (software|services|accounts)/i, /auto-?run/i], resolve: secureConfig },
  { id: "passwords", label: "Passwords", patterns: [/password/i, /passphrase/i], resolve: passwords },
  { id: "vulnerability_scanning", label: "Vulnerability scanning", patterns: [/vulnerability (scan|assessment|management|test)/i, /scan(s|ned|ning)? for vulnerabilit/i, /external scan/i, /attack surface/i], resolve: scanning },
  { id: "web_security", label: "Website security", patterns: [/web ?(site|application) security/i, /security headers/i, /\bowasp\b/i, /website/i], resolve: webSecurity },
  // Last: "supplier" is often the respondent ("Does the supplier use MFA?"), so a technical topic must win any tie.
  { id: "third_parties", label: "Your suppliers", patterns: [/third[- ]part(y|ies)/i, /sub-?contractors?/i, /supply chain/i, /(your|own) (suppliers|vendors)/i], resolve: orgOnly("How you manage your own suppliers") },
  { id: "asset_inventory", label: "Asset inventory", patterns: [/asset (inventory|register|list)/i, /inventory of/i, /hardware (register|inventory)/i, /device inventory/i, /list of (devices|assets|hardware)/i], resolve: assetInventory },
];

/** Pure: the topic a question is about, or null. Most matched patterns wins; ties go to the earlier topic. */
export function classifyQuestion(question: string): Topic | null {
  let best: Topic | null = null;
  let bestScore = 0;
  for (const t of TOPICS) {
    const score = t.patterns.filter((p) => p.test(question)).length;
    if (score > bestScore) {
      best = t;
      bestScore = score;
    }
  }
  return best;
}

const ASKS_FOR_POLICY = /(written|documented|formal)\b.*\b(polic|procedure|process)|\bpolic(y|ies)\b/i;

/** Pure: the rule-based draft for one question, from the customer's evidence only. */
export function draftFromEvidence(question: string, facts: EvidenceFacts): DraftAnswer {
  const topic = classifyQuestion(question);
  if (!topic) return { topic: null, reusedFrom: null, ...needsAnswer("We don't hold evidence that answers this question.") };
  const resolved = topic.resolve({ question, facts });
  // A question about a documented policy isn't answered by evidence of practice alone.
  if (resolved.status === "draft" && topic.id !== "policy" && ASKS_FOR_POLICY.test(question)) {
    const docs = docsOf(facts, "policy");
    return {
      topic: topic.id,
      reusedFrom: null,
      ...resolved,
      confidence: "low",
      evidence: [...resolved.evidence, ...docs],
      note: "The question asks about a documented policy. The evidence shows what is in practice, not that a policy is written down. Confirm before accepting.",
    };
  }
  return { topic: topic.id, reusedFrom: null, ...resolved };
}
