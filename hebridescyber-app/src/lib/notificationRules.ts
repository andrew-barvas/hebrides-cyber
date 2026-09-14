// E-51: notification filtering rules — pure functions that decide whether a
// scan result warrants an alert based on user-configured thresholds.
//
// Pure and dependency-free so every branch is unit-testable without mocking
// Supabase, following scanCadence.ts / ticketLinks.ts precedent.

export type NotificationPrefs = {
  scoreThreshold: number | null;
  severityMin: string | null;
};

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRankOf(severity: string): number {
  return SEVERITY_RANK[severity] ?? -1;
}

/**
 * Returns true if the scan report warrants a notification given the user's
 * preferences. A report always passes if no thresholds are configured (the
 * default: alert on every completed scan). When thresholds are set:
 *
 * - `scoreThreshold`: suppress if the score is AT or ABOVE this value
 *   (i.e. only alert when score < threshold — "notify me when it's bad").
 *
 * - `severityMin`: suppress unless at least one NEW finding meets this
 *   severity or higher. A scan with no new findings is suppressed. Only
 *   applies when there's a previous scan to diff against.
 */
export function shouldNotify(
  report: { score: number | null; new_finding_count?: number | null; findings: { severity: string; status?: string | null }[] },
  prefs: NotificationPrefs
): boolean {
  const { scoreThreshold, severityMin } = prefs;

  if (scoreThreshold != null && report.score != null) {
    if (report.score >= scoreThreshold) return false;
  }

  if (severityMin != null) {
    const minRank = severityRankOf(severityMin);
    if (minRank < 0) return true; // unknown severity value — don't suppress

    if (!report.new_finding_count) return false; // no new findings to check

    const hasQualifyingFinding = report.findings.some(
      (f) => f.status === "new" && severityRankOf(f.severity) >= minRank
    );
    if (!hasQualifyingFinding) return false;
  }

  return true;
}
