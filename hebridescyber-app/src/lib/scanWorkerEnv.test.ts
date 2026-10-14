// The scan workers are the only place executeScan() runs, so every secret its
// post-scan notifiers read has to be in their step's env. RESEND_API_KEY was
// missing for months: every critical-finding, scan-complete, SLA and
// attack-surface email was silently skipped (email.ts returns
// "not configured" rather than throwing). CREDENTIALS_ENC_KEY is the same kind
// of secret: the workers decrypt stored customer credentials with it, and
// without it every encrypted credential is skipped as undecryptable.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const WORKFLOWS = path.resolve(process.cwd(), "../.github/workflows");

/** The env block of the step named `name`, as written in the workflow. */
function stepText(file: string, name: string): string {
  const text = readFileSync(path.join(WORKFLOWS, file), "utf8");
  const start = text.indexOf(`- name: ${name}`);
  if (start < 0) throw new Error(`${file} has no step "${name}"`);
  const next = text.indexOf("\n      - name:", start + 1);
  return text.slice(start, next < 0 ? undefined : next);
}

describe.each(["scheduled-scans.yml", "on-demand-scan.yml"])("%s scan worker", (file) => {
  const step = stepText(file, "Work the scan job queue");

  it.each(["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "RESEND_API_KEY", "CREDENTIALS_ENC_KEY"])("passes %s from the secret store", (name) => {
    expect(step).toContain(`${name}: \${{ secrets.${name} }}`);
  });

  it("passes the site URL the alert links use", () => {
    expect(step).toContain("NEXT_PUBLIC_SITE_URL: ${{ vars.NEXT_PUBLIC_SITE_URL }}");
  });

  it("runs the queue worker", () => {
    expect(step).toContain("run: npm run queue:run-worker");
  });
});
