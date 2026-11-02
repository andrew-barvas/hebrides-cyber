// Runs a customer's own nuclei templates (see src/lib/customNucleiTemplates.ts)
// against the one target being scanned.
//
// Every template is re-validated here, not only when it was saved: a row
// written before a rule was tightened, or by any route that skipped the
// validator, must still not reach nuclei. The flags are a second fence: no
// out-of-band server, no code or headless templates (nuclei leaves both off
// unless asked), no local file access, no update check, and a low request rate.
import { execTool } from "../../lib/execTool";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { validateCustomTemplate } from "../../lib/customNucleiTemplates";
import { parseNucleiOutput } from "./nuclei";

const TIMEOUT_MS = 90_000;

export type CustomTemplateRow = { template_id: string; yaml: string };

export type CustomNucleiFinding = {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  templateId: string;
};

export type CustomNucleiResult =
  | { status: "completed"; findings: CustomNucleiFinding[]; skipped: string[] }
  | { status: "not_configured"; findings: []; skipped: string[] }
  | { status: "error"; findings: []; skipped: string[]; note: string };

export function buildCustomNucleiArgs(targetUrl: string, templateDir: string, outFile: string): string[] {
  return [
    "-target", targetUrl,
    "-t", templateDir,
    "-json-export", outFile,
    "-silent",
    "-timeout", "10",
    "-retries", "0",
    "-rl", "5",
    "-c", "3",
    // No out-of-band server: a template cannot make the target call anyone.
    "-ni",
    "-duc",
    "-no-color",
  ];
}

export async function runCustomNuclei(targetUrl: string, templates: CustomTemplateRow[]): Promise<CustomNucleiResult> {
  const skipped: string[] = [];
  const valid = templates.filter((t) => {
    const check = validateCustomTemplate(t.yaml);
    // The id inside the YAML is what nuclei reports, so it must be the row's.
    if (!check.ok || check.id !== t.template_id) {
      skipped.push(t.template_id);
      return false;
    }
    return true;
  });
  if (valid.length === 0) return { status: "completed", findings: [], skipped };

  let dir: string | null = null;
  try {
    dir = await mkdtemp(path.join(tmpdir(), "custom-nuclei-"));
    for (const t of valid) await writeFile(path.join(dir, `${t.template_id}.yaml`), t.yaml, { encoding: "utf8", mode: 0o600 });
    const outFile = path.join(dir, "results.json");
    await execTool("nuclei", buildCustomNucleiArgs(targetUrl, dir, outFile), { timeout: TIMEOUT_MS });

    let raw = "";
    try {
      raw = await readFile(outFile, "utf8");
    } catch {
      // nuclei ran and matched nothing.
    }
    const ids = new Set(valid.map((t) => t.template_id));
    // Only results from the customer's own templates count: the directory holds nothing else, but this keeps that true by construction.
    const findings = parseNucleiOutput(raw, targetUrl).filter((f) => ids.has(f.templateId));
    return { status: "completed", findings: findings.map(({ severity, title, detail, templateId }) => ({ severity, title, detail, templateId })), skipped };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") return { status: "not_configured", findings: [], skipped };
    return { status: "error", findings: [], skipped, note: `custom nuclei checks failed: ${error.message}` };
  } finally {
    if (dir) rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}
