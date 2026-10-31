// Bridges a customer's saved nuclei checks into a scan: plan check, load,
// run (src/worker/tools/customNuclei.ts), and shape results as Findings.
// Never throws and never fails a scan; a problem is logged and the scan
// carries on without the custom checks.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./scanners";
import { planGate } from "./planAccess";
import { runCustomNuclei, type CustomTemplateRow } from "../worker/tools/customNuclei";

export async function runCustomChecksForOwner(supabaseAdmin: SupabaseClient, ownerId: string, targetUrl: string, run: typeof runCustomNuclei = runCustomNuclei): Promise<Finding[]> {
  try {
    // Checked again at scan time: a plan that has lapsed stops its checks running.
    if ((await planGate(supabaseAdmin, ownerId, "agency")) !== "ok") return [];
    const { data, error } = await supabaseAdmin.from("custom_nuclei_templates").select("template_id, yaml").eq("owner", ownerId).eq("enabled", true);
    if (error) {
      console.error("[custom-checks] could not load templates:", error.message);
      return [];
    }
    const rows = (data ?? []) as CustomTemplateRow[];
    if (rows.length === 0) return [];

    const result = await run(targetUrl, rows);
    if (result.skipped.length > 0) console.warn(`[custom-checks] skipped templates that no longer validate: ${result.skipped.join(", ")}`);
    if (result.status === "error") console.error(`[custom-checks] ${result.note}`);

    return result.findings.map((f) => ({
      checkId: `custom-nuclei:${f.templateId}`,
      severity: f.severity,
      title: `[Custom check] ${f.title}`,
      detail: f.detail,
      remediation: "This finding comes from a check you wrote. Review the matched response against your template, then fix the exposure it describes.",
    }));
  } catch (err) {
    console.error("[custom-checks] failed:", (err as Error).message);
    return [];
  }
}
