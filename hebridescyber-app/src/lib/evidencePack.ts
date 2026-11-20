// The security evidence pack (next-10 task 7): one PDF for a customer to
// attach to a Cyber Essentials application, a cyber insurance proposal form
// or a supplier security questionnaire.
//
// It only restates evidence we already hold, and says where each answer
// comes from:
//   - "evidenced"      our checks saw it was in place
//   - "gap"            our checks saw a problem (open findings listed)
//   - "declared"       the customer's own Cyber Essentials self-assessment
//   - "not_evidenced"  nothing we check can see it; answer from your records
// A check we couldn't run is never written up as "in place" (rule 7).
import type { SupabaseClient } from "@supabase/supabase-js";
import { assessCeReadiness } from "./cyberEssentialsReadiness";
import { combineReadiness, type CeAnswer, type CeAnswerValue, type CombinedCeReport } from "./ceSelfAssessment";
import { buildHostSignals, loadTargetContexts, rankFindings, type PrioritisedFinding } from "./estatePriority";
import { escapeHtml, REPORT_MUTED, REPORT_TEXT } from "./executiveReport";
import { loadFindingsView, type FindingRow } from "./findingsView";
import type { Finding } from "./scanners";

export type AnswerSource = "evidenced" | "gap" | "declared" | "not_evidenced";
export type InsuranceAnswer = { id: string; question: string; source: AnswerSource; answer: string; detail: string[] };

export type EvidenceInputs = {
  /** Open findings across every site (false positives already left out). */
  rows: FindingRow[];
  /** Hosts with at least one completed scan, and when. */
  scannedSites: Array<{ host: string; lastScanAt: string }>;
  /** Microsoft 365 / Google Workspace connected and checked at least once. */
  m365Checked: string | null;
  workspaceChecked: string | null;
  answers: CeAnswer[];
};

const has = (rows: FindingRow[], test: (checkId: string) => boolean) => rows.filter((r) => test(r.checkId));
const titles = (rows: FindingRow[]) => [...new Set(rows.map((r) => `${r.title} (${r.host})`))].slice(0, 6);
const answerOf = (answers: CeAnswer[], key: string): CeAnswerValue | null => answers.find((a) => a.questionKey === key)?.answer ?? null;
const DECLARED: Record<CeAnswerValue, string> = { yes: "Yes (self-declared)", no: "No (self-declared)", partial: "Partly (self-declared)", na: "Not applicable (self-declared)" };

function declaredOr(answers: CeAnswer[], key: string, fallback: Omit<InsuranceAnswer, "id" | "question">): Omit<InsuranceAnswer, "id" | "question"> {
  const a = answerOf(answers, key);
  return a ? { source: "declared", answer: DECLARED[a], detail: ["From your Cyber Essentials self-assessment in Hebrides Cyber."] } : fallback;
}

const NOT_EVIDENCED = (what: string): Omit<InsuranceAnswer, "id" | "question"> => ({
  source: "not_evidenced",
  answer: "Answer from your own records",
  detail: [`${what} can't be seen from outside your organisation, so Hebrides Cyber doesn't check it.`],
});

/** Pure: the common insurer and questionnaire questions, each answered from what we hold. */
export function insuranceAnswers(input: EvidenceInputs): InsuranceAnswer[] {
  const { rows, answers } = input;
  const scanned = input.scannedSites.length > 0;
  const out: InsuranceAnswer[] = [];
  const add = (id: string, question: string, a: Omit<InsuranceAnswer, "id" | "question">) => out.push({ id, question, ...a });

  // MFA on email: only evidenced from a connected, checked tenant.
  const mfaGaps = has(rows, (c) => /^m365\.mfaNotEnforced|^m365\.legacyAuthAllowed|^workspace\.(2svNotEnforced|adminsWithout2sv)/.test(c));
  const checkedAt = input.m365Checked ?? input.workspaceChecked;
  add(
    "mfa_email",
    "Is multi-factor authentication (MFA) enforced for all email accounts?",
    mfaGaps.length
      ? { source: "gap", answer: "No: gaps found", detail: titles(mfaGaps) }
      : checkedAt
        ? { source: "evidenced", answer: "Yes", detail: [`Checked in your ${input.m365Checked ? "Microsoft 365" : "Google Workspace"} tenant on ${checkedAt.slice(0, 10)}; no accounts without MFA were found.`] }
        : declaredOr(answers, "user-access.mfa", NOT_EVIDENCED("MFA on email (connect Microsoft 365 or Google Workspace to have it checked)")),
  );

  const spoofing = has(rows, (c) => /^dns\.(spf-missing|spf-issues|dmarc-missing|dmarc-none|dkim-not-detected)/.test(c));
  add(
    "email_spoofing",
    "Do your email domains have SPF, DKIM and DMARC in place to prevent spoofing?",
    spoofing.length
      ? { source: "gap", answer: "Partly: gaps found", detail: titles(spoofing) }
      : scanned
        ? { source: "evidenced", answer: "Yes", detail: ["No missing or misconfigured SPF, DKIM or DMARC records were found on your scanned domains."] }
        : NOT_EVIDENCED("Email authentication (no site has been scanned yet)"),
  );

  const remote = has(rows, (c) => /^ports\.risky-port|^network-exposure\.open-port:(22|23|445|3389|5900|5985|5986)\b/.test(c));
  add(
    "remote_access",
    "Are remote access services (RDP, SSH, VNC, file sharing) closed to the internet or protected?",
    remote.length
      ? { source: "gap", answer: "No: exposed services found", detail: titles(remote) }
      : scanned
        ? { source: "evidenced", answer: "Yes", detail: ["No remote access services were found open to the internet on your scanned sites."] }
        : NOT_EVIDENCED("Exposed services (no site has been scanned yet)"),
  );

  const patching = has(rows, (c) => /^eol\.unsupported|^network-exposure\.service-(cve|eol)|^nuclei\.cve|^software-cve|^wp-vuln/.test(c));
  const exploited = patching.filter((r) => r.knownExploited);
  add(
    "patching",
    "Are critical security updates applied within 14 days of release?",
    patching.length
      ? {
          source: "gap",
          answer: exploited.length ? "No: actively exploited vulnerabilities are unpatched" : "Partly: outdated software found",
          detail: titles(exploited.length ? exploited : patching),
        }
      : declaredOr(answers, "updates.patch-window", scanned ? { source: "evidenced", answer: "Yes, on internet-facing systems", detail: ["No known-vulnerable or unsupported software was found on your scanned sites. Internal devices aren't visible to us."] } : NOT_EVIDENCED("Patching")),
  );

  const tls = has(rows, (c) => /^tls\.(no-https|cert-expired|cert-untrusted|self-signed|weak-protocol|weak-cipher)/.test(c));
  add(
    "encryption",
    "Is data encrypted in transit on your websites and services?",
    tls.length
      ? { source: "gap", answer: "Partly: issues found", detail: titles(tls) }
      : scanned
        ? { source: "evidenced", answer: "Yes", detail: ["Your scanned sites use HTTPS with valid certificates and no weak protocols."] }
        : NOT_EVIDENCED("Encryption in transit (no site has been scanned yet)"),
  );

  const breaches = has(rows, (c) => c.startsWith("hibp.domain-breach"));
  if (breaches.length) add("breached_credentials", "Have any staff credentials appeared in known data breaches?", { source: "gap", answer: "Yes: affected addresses found", detail: [...titles(breaches), "Those passwords should be changed and MFA turned on."] });

  add("endpoint_protection", "Is anti-malware or endpoint protection installed and kept up to date on all devices?", declaredOr(answers, "malware.protection", NOT_EVIDENCED("Anti-malware on devices")));
  add("admin_rights", "Are administrator accounts separate from everyday accounts and limited to those who need them?", declaredOr(answers, "user-access.admin-separation", NOT_EVIDENCED("Admin account separation")));
  add("backups", "Do you keep regular, tested backups stored separately (offline or immutable)?", NOT_EVIDENCED("Backups"));
  add("training", "Do staff receive regular security awareness training?", NOT_EVIDENCED("Staff training"));
  add("incident_response", "Do you have a written incident response plan?", NOT_EVIDENCED("An incident response plan"));
  return out;
}

/** Pure: Cyber Essentials readiness from open findings plus the customer's answers. */
export function ceReadinessFromRows(rows: FindingRow[], answers: CeAnswer[]): CombinedCeReport {
  const findings = rows.map((r) => ({ checkId: r.checkId, severity: r.severity, title: r.title, detail: r.detail ?? "" })) as unknown as Finding[];
  return combineReadiness(rows.length || answers.length ? assessCeReadiness(findings) : null, answers);
}

export type EvidencePack = {
  company: string | null;
  generatedAt: string;
  sites: Array<{ host: string; lastScanAt: string }>;
  ce: CombinedCeReport;
  insurance: InsuranceAnswer[];
  fixFirst: PrioritisedFinding[];
};

// Shared with the PDF renderer (evidencePackPdf.ts) so the two say the same thing.
export const SOURCE_LABEL: Record<AnswerSource, string> = { evidenced: "Evidenced", gap: "Gap found", declared: "Self-declared", not_evidenced: "Your records" };
export const SOURCE_COLOUR: Record<AnswerSource, string> = { evidenced: "#166534", gap: "#b91c1c", declared: "#1d4ed8", not_evidenced: "#475569" };
export const STATUS_LABEL: Record<string, string> = { pass: "Met", partial: "Partly met", fail: "Not met", "not-assessed": "Not assessed" };
export const STATUS_COLOUR: Record<string, string> = { pass: "#166534", partial: "#b45309", fail: "#b91c1c", "not-assessed": REPORT_MUTED };
export const declaredLabel = (answer: CeAnswerValue | null): string => (answer ? DECLARED[answer] : "Not answered yet");
export const readinessLabel = (status: CombinedCeReport["overall_status"]): string => (status === "ready" ? "ready" : status === "partial" ? "partly ready" : "not ready yet");
export const EVIDENCE_PACK_FOOTER =
  "Prepared by Hebrides Cyber from automated external checks of what is reachable from the internet, connected Microsoft 365 or Google Workspace checks, and your own self-assessment answers. It is supporting evidence, not a certification: Cyber Essentials certification is awarded by an IASME certification body, and you remain responsible for the accuracy of what you submit.";

/** Pure. */
export function renderEvidencePackHtml(pack: EvidencePack): string {
  const e = escapeHtml;
  const controls = pack.ce.controls
    .map(
      (c) => `<div class="block"><h3>${e(c.control)}: <span class="${c.status}">${e(STATUS_LABEL[c.status] ?? c.status)}</span></h3>
      ${c.questions.length ? `<ul>${c.questions.map((q) => `<li>${e(q.prompt)} <b>${e(declaredLabel(q.answer))}</b></li>`).join("")}</ul>` : ""}
      ${c.gaps.length ? `<p class="muted">To address: ${e(c.gaps.slice(0, 5).join("; "))}</p>` : ""}</div>`,
    )
    .join("");
  const insurance = pack.insurance
    .map(
      (a) => `<tr><td>${e(a.question)}</td><td><span class="tag" style="background:${SOURCE_COLOUR[a.source]}">${SOURCE_LABEL[a.source]}</span><br><b>${e(a.answer)}</b></td><td class="muted">${a.detail.map((d) => e(d)).join("<br>")}</td></tr>`,
    )
    .join("");
  const fix = pack.fixFirst
    .slice(0, 10)
    .map((f) => `<li><b>${e(f.title)}</b> <span class="muted">(${e(f.host)}, ${e(f.severity)})</span></li>`)
    .join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>Security evidence pack ${e(pack.generatedAt.slice(0, 10))}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font-family: Arial, Helvetica, sans-serif; color: ${REPORT_TEXT}; font-size: 12px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0; color: #0b3d5b; } h2 { font-size: 15px; margin: 22px 0 8px; color: #0b3d5b; border-bottom: 1px solid #d5dde5; padding-bottom: 4px; }
  h3 { font-size: 13px; margin: 0 0 4px; } .head { border-bottom: 3px solid #0b3d5b; padding-bottom: 12px; }
  .muted { color: ${REPORT_MUTED}; } .block { page-break-inside: avoid; margin-bottom: 12px; } ul, ol { margin: 4px 0 0 18px; padding: 0; } li { margin-bottom: 3px; }
  .pass { color: #166534; } .partial { color: #b45309; } .fail { color: #b91c1c; } .not-assessed { color: ${REPORT_MUTED}; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 6px; border-bottom: 1px solid #e4e9ee; vertical-align: top; }
  th { font-size: 10px; text-transform: uppercase; color: ${REPORT_MUTED}; } tr { page-break-inside: avoid; }
  .tag { display: inline-block; color: #fff; font-size: 9px; font-weight: bold; text-transform: uppercase; padding: 2px 6px; border-radius: 4px; }
  .foot { margin-top: 26px; border-top: 1px solid #d5dde5; padding-top: 8px; font-size: 10px; color: ${REPORT_MUTED}; }
</style></head>
<body>
  <div class="head"><h1>Security evidence pack</h1>
    <div class="muted">${pack.company ? `${e(pack.company)} · ` : ""}generated ${e(pack.generatedAt.slice(0, 10))} · ${pack.sites.length} site${pack.sites.length === 1 ? "" : "s"} checked</div>
  </div>
  <p>Evidence for a Cyber Essentials application, a cyber insurance proposal or a supplier questionnaire. Each answer says where it comes from: <b>Evidenced</b> (our checks saw it), <b>Gap found</b> (our checks saw a problem), <b>Self-declared</b> (your own answers in Hebrides Cyber) or <b>Your records</b> (something no outside check can see).</p>

  <h2>Sites checked</h2>
  ${pack.sites.length ? `<ul>${pack.sites.map((s) => `<li>${e(s.host)} <span class="muted">(last scanned ${e(s.lastScanAt.slice(0, 10))})</span></li>`).join("")}</ul>` : '<p class="muted">No site has been scanned yet.</p>'}

  <h2>Insurance and supplier questionnaire answers</h2>
  <table><thead><tr><th>Question</th><th>Answer</th><th>Evidence</th></tr></thead><tbody>${insurance}</tbody></table>

  <h2>Cyber Essentials readiness: ${e(readinessLabel(pack.ce.overall_status))}</h2>
  <p class="muted">${pack.ce.answered} of ${pack.ce.total_questions} self-assessment questions answered. ${e(pack.ce.recommendation)}</p>
  ${controls}

  ${fix ? `<h2>Fix these first</h2><ol>${fix}</ol>` : ""}

  <div class="foot">${EVIDENCE_PACK_FOOTER}</div>
</body></html>`;
}

export async function loadEvidencePack(supabaseAdmin: SupabaseClient, ownerId: string, now: Date = new Date()): Promise<EvidencePack> {
  const [view, targets, answersRes, user, scans, m365, workspace] = await Promise.all([
    loadFindingsView(supabaseAdmin, ownerId, now),
    loadTargetContexts(supabaseAdmin, ownerId),
    supabaseAdmin.from("ce_self_assessment").select("question_key, answer, note").eq("owner", ownerId),
    supabaseAdmin.from("users").select("company_name").eq("id", ownerId).maybeSingle(),
    supabaseAdmin.from("scans").select("target_url, created_at").eq("owner", ownerId).eq("status", "completed").order("created_at", { ascending: false }).limit(500),
    supabaseAdmin.from("m365_tenants").select("last_checked_at").eq("owner", ownerId).order("last_checked_at", { ascending: false }).limit(1).maybeSingle(),
    supabaseAdmin.from("workspace_connections").select("last_checked_at").eq("owner", ownerId).maybeSingle(),
  ]);
  if (!view.ok) throw new Error(view.error);
  const rows = view.data.rows.filter((r) => r.triage?.state !== "false_positive");
  const answers: CeAnswer[] = ((answersRes.data ?? []) as Array<{ question_key: string; answer: CeAnswerValue; note: string | null }>).map((a) => ({ questionKey: a.question_key, answer: a.answer, note: a.note }));

  const latest = new Map<string, string>();
  for (const s of (scans.data ?? []) as Array<{ target_url: string; created_at: string }>) {
    try {
      const host = new URL(s.target_url).hostname.toLowerCase();
      if (!latest.has(host)) latest.set(host, s.created_at);
    } catch {
      // not a URL; skip
    }
  }
  const sites = [...latest].map(([host, lastScanAt]) => ({ host, lastScanAt })).sort((a, b) => a.host.localeCompare(b.host));
  const m365Checked = ((m365.data as { last_checked_at?: string | null } | null)?.last_checked_at) ?? null;
  const workspaceChecked = ((workspace.data as { last_checked_at?: string | null } | null)?.last_checked_at) ?? null;

  return {
    company: ((user.data as { company_name?: string | null } | null)?.company_name) ?? null,
    generatedAt: now.toISOString(),
    sites,
    ce: ceReadinessFromRows(rows, answers),
    insurance: insuranceAnswers({ rows, scannedSites: sites, m365Checked, workspaceChecked, answers }),
    fixFirst: rankFindings(rows, targets.contexts, buildHostSignals(view.data.detailByHost)),
  };
}
