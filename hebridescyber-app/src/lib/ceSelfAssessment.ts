// Cyber Essentials self-assessment: the human half of readiness.
//
// cyberEssentialsReadiness.ts's assessCeReadiness(findings) derives per-control
// evidence from a scan — but a scan sees only what faces the internet. The CE
// certification is a self-assessment questionnaire that also asks about things
// no external scan can observe: host firewalls, device configuration, who has
// admin rights, endpoint anti-malware, patch cadence. CE_QUESTIONS catalogues
// exactly those questions (one framing per the /cyber-essentials marketing
// page's "what only you can answer" column), and combineReadiness() merges the
// customer's answers with the scan evidence into one per-control status.
//
// Pure throughout (model: scanCadence.ts's isScanDue, assessCeReadiness) — fed
// the scan report and the saved answers, returns the combined report. No I/O,
// so every branch is unit-testable without Supabase.
import type { CeControl, CeControlAssessment, CeReadinessReport } from "./cyberEssentialsReadiness";

export const CE_CONTROLS: readonly CeControl[] = [
  "Firewalls and internet gateways",
  "Secure configuration",
  "User access control",
  "Malware protection",
  "Security update management",
];

/** An allowed answer. "na" = not applicable to this account (counts as satisfied). */
export type CeAnswerValue = "yes" | "no" | "partial" | "na";
export const CE_ANSWER_VALUES: readonly CeAnswerValue[] = ["yes", "no", "partial", "na"];

export type CeQuestion = {
  /** Stable key stored in ce_self_assessment.question_key — never renumber. */
  key: string;
  control: CeControl;
  /** The question as the customer reads it. */
  prompt: string;
  /** Short hint on what "yes" means, shown under the question. */
  help: string;
};

/** One saved answer, as stored in ce_self_assessment and sent by the API. */
export type CeAnswer = {
  questionKey: string;
  answer: CeAnswerValue;
  note?: string | null;
};

// The questions only the customer can answer, grouped by control. Keys are
// stable (`<control-slug>.<n>`); the prompts mirror the five controls' own
// requirements as the NCSC self-assessment frames them. Deliberately short —
// this is a readiness aid, not the official questionnaire.
export const CE_QUESTIONS: readonly CeQuestion[] = [
  {
    key: "firewalls.boundary",
    control: "Firewalls and internet gateways",
    prompt: "Is there a correctly configured firewall at the boundary of every network in scope (office and, for home workers, their router or a software firewall)?",
    help: "A boundary firewall or internet gateway controls traffic in and out of each network your in-scope devices connect through.",
  },
  {
    key: "firewalls.host",
    control: "Firewalls and internet gateways",
    prompt: "Is a host-based firewall enabled on every in-scope device (laptops, desktops, servers)?",
    help: "Devices used away from the office can't rely on the boundary firewall, so each needs its own enabled.",
  },
  {
    key: "firewalls.default-password",
    control: "Firewalls and internet gateways",
    prompt: "Has the default administrative password on every firewall and router been changed to a strong, unique one?",
    help: "Default device passwords are published and are among the first things an attacker tries.",
  },
  {
    key: "secure-config.default-accounts",
    control: "Secure configuration",
    prompt: "Have default and unnecessary user accounts been removed or disabled, and all default passwords changed, on every device and service?",
    help: "Unused accounts and shipped defaults are a common way in and must be removed or secured.",
  },
  {
    key: "secure-config.software-removed",
    control: "Secure configuration",
    prompt: "Has unused software, and have unnecessary services and auto-run/auto-play features, been removed or disabled from in-scope devices?",
    help: "Every extra service is more attack surface; CE requires devices to run only what they need.",
  },
  {
    key: "secure-config.device-lock",
    control: "Secure configuration",
    prompt: "Is a device-unlock credential (PIN, password or biometric) required on every device, with brute-force protection such as a lockout or wipe?",
    help: "A lost or stolen device must not give up its data to a few password guesses.",
  },
  {
    key: "user-access.unique-accounts",
    control: "User access control",
    prompt: "Does every user have their own named account, created only through an approved process, with shared accounts avoided?",
    help: "Accounts must be traceable to a person and provisioned deliberately, not shared.",
  },
  {
    key: "user-access.admin-separation",
    control: "User access control",
    prompt: "Are administrative privileges granted only to those who need them, used from separate admin accounts, and reviewed and removed when no longer required?",
    help: "Day-to-day work should not use an admin account, and leavers' access must be revoked promptly.",
  },
  {
    key: "user-access.mfa",
    control: "User access control",
    prompt: "Is multi-factor authentication enabled on all cloud services and, where available, for administrative access?",
    help: "CE requires MFA on cloud services; it is the single strongest defence against stolen passwords.",
  },
  {
    key: "malware.protection",
    control: "Malware protection",
    prompt: "Is anti-malware software, or application allow-listing, active on every in-scope device?",
    help: "At least one malware-protection mechanism must be in place and kept up to date on each device.",
  },
  {
    key: "malware.updates",
    control: "Malware protection",
    prompt: "Is that malware protection kept up to date automatically (signatures or allow-lists), and set to scan files on access?",
    help: "Out-of-date protection catches nothing new; CE expects it to update and scan automatically.",
  },
  {
    key: "updates.supported",
    control: "Security update management",
    prompt: "Is all software on in-scope devices licensed, supported by its vendor, and removed once it is no longer supported?",
    help: "Unsupported software stops getting security fixes and must be removed or upgraded.",
  },
  {
    key: "updates.patch-window",
    control: "Security update management",
    prompt: "Are security updates applied within 14 days of release for any update marked critical or high-risk, with automatic updates enabled where possible?",
    help: "CE requires high-risk patches within 14 days — the window attackers race to exploit.",
  },
];

export type CeAnswerStatus = "satisfied" | "gap" | "partial" | "unanswered";

export type CeQuestionResult = CeQuestion & {
  answer: CeAnswerValue | null;
  note: string | null;
  status: CeAnswerStatus;
};

export type CombinedControl = {
  control: CeControl;
  /** The scan-derived status for this control (null if the control wasn't assessed). */
  scanStatus: CeControlAssessment["status"] | null;
  /** The questionnaire answers for this control. */
  questions: CeQuestionResult[];
  /** Combined status: the worse of the scan evidence and the answers. */
  status: "pass" | "partial" | "fail" | "not-assessed";
  /** Scan gaps plus any unanswered/failed questions, as plain prose. */
  gaps: string[];
};

export type CombinedCeReport = {
  overall_status: "ready" | "partial" | "not-ready";
  /** 0–100: share of controls at "pass". */
  score: number;
  /** How many questions the customer has answered, out of the catalogue. */
  answered: number;
  total_questions: number;
  controls: CombinedControl[];
  recommendation: string;
};

function answerStatus(answer: CeAnswerValue | null): CeAnswerStatus {
  if (answer === null) return "unanswered";
  if (answer === "yes" || answer === "na") return "satisfied";
  if (answer === "partial") return "partial";
  return "gap"; // "no"
}

/** Severity rank among the states that carry information. */
const STATUS_RANK: Record<"pass" | "partial" | "fail", number> = { pass: 0, partial: 1, fail: 2 };

/**
 * The worse of two control states. "not-assessed" is neutral — no information,
 * so it defers to the other side (and only survives when both sides are it).
 */
function worse(a: CombinedControl["status"], b: CombinedControl["status"]): CombinedControl["status"] {
  if (a === "not-assessed") return b;
  if (b === "not-assessed") return a;
  return STATUS_RANK[a] >= STATUS_RANK[b] ? a : b;
}

/**
 * Merges scan-derived evidence (assessCeReadiness) with the customer's saved
 * answers into one per-control readiness view. Pure.
 *
 * Per control, the questionnaire contributes its own status: any "no" is a
 * fail, any "partial" or unanswered question is a partial, all satisfied is a
 * pass. The combined control status is the worse of that and the scan status,
 * so a clean scan can't paper over an admitted gap and vice versa.
 */
export function combineReadiness(scanReport: CeReadinessReport | null, answers: CeAnswer[]): CombinedCeReport {
  const byKey = new Map<string, CeAnswer>();
  for (const a of answers) {
    // Ignore answers whose key isn't in the catalogue (a renamed/removed question).
    if (CE_QUESTIONS.some((q) => q.key === a.questionKey)) byKey.set(a.questionKey, a);
  }

  const scanByControl = new Map<CeControl, CeControlAssessment>();
  for (const c of scanReport?.controls ?? []) scanByControl.set(c.control, c);

  const controls: CombinedControl[] = CE_CONTROLS.map((control) => {
    const questions: CeQuestionResult[] = CE_QUESTIONS.filter((q) => q.control === control).map((q) => {
      const saved = byKey.get(q.key);
      const answer = saved?.answer ?? null;
      return { ...q, answer, note: saved?.note ?? null, status: answerStatus(answer) };
    });

    // Questionnaire status for this control.
    let questionnaireStatus: CombinedControl["status"];
    if (questions.some((q) => q.status === "gap")) questionnaireStatus = "fail";
    else if (questions.some((q) => q.status === "partial" || q.status === "unanswered")) questionnaireStatus = "partial";
    else questionnaireStatus = "pass";

    const scan = scanByControl.get(control);
    const scanStatus = scan?.status ?? null;
    // "not-assessed" from the scan is neutral — the questionnaire still speaks.
    const scanContribution: CombinedControl["status"] =
      scanStatus === "pass" ? "pass" : scanStatus === "fail" ? "fail" : scanStatus === "partial" ? "partial" : "not-assessed";

    const status = worse(questionnaireStatus, scanContribution);

    const gaps: string[] = [];
    for (const g of scan?.gaps ?? []) gaps.push(`Scan: ${g}`);
    for (const q of questions) {
      if (q.status === "gap") gaps.push(`You answered "No": ${q.prompt}`);
      else if (q.status === "partial") gaps.push(`Partially in place: ${q.prompt}`);
      else if (q.status === "unanswered") gaps.push(`Not yet answered: ${q.prompt}`);
    }

    return { control, scanStatus, questions, status, gaps };
  });

  const passCount = controls.filter((c) => c.status === "pass").length;
  const failCount = controls.filter((c) => c.status === "fail").length;
  const score = Math.round((passCount / controls.length) * 100);
  const answered = CE_QUESTIONS.filter((q) => byKey.has(q.key)).length;

  const overall_status: CombinedCeReport["overall_status"] =
    failCount > 0 ? "not-ready" : passCount === controls.length ? "ready" : "partial";

  let recommendation: string;
  if (overall_status === "ready") {
    recommendation =
      "Both your scan evidence and your self-assessment answers indicate readiness for Cyber Essentials. Confirm the answers reflect every in-scope device, then submit the formal self-assessment to your certification body.";
  } else if (overall_status === "not-ready") {
    recommendation = `${failCount} control${failCount === 1 ? "" : "s"} would likely fail certification. Resolve the gaps below — a "No" answer or a critical scan finding is a certification blocker.`;
  } else if (answered < CE_QUESTIONS.length) {
    recommendation = `Answer the remaining ${CE_QUESTIONS.length - answered} question${CE_QUESTIONS.length - answered === 1 ? "" : "s"} and close the gaps below to reach full readiness.`;
  } else {
    recommendation = `${CE_CONTROLS.length - passCount} control${CE_CONTROLS.length - passCount === 1 ? " needs" : "s need"} attention before you apply. Close the gaps below, then re-scan and re-check.`;
  }

  return { overall_status, score, answered, total_questions: CE_QUESTIONS.length, controls, recommendation };
}
