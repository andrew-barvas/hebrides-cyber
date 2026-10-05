// Keeps the TypeScript catalogue and the rule pack's YAML in step: every rule
// in sast-rules/ must be catalogued (so it gets compliance refs, a fix
// difficulty and the right remediation), with the category its CWE implies.
// The YAML is read with a small line-based extractor rather than a YAML
// dependency — the rule files follow one fixed layout.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { extractCweIds, sastCategoryForCwes, SAST_RULE_CATEGORIES, SAST_CWE_CATEGORY, SAST_CATEGORY_LABELS } from "./sastCatalog";
import { getComplianceRefs } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";
import { sastRemediation, sastLanguageForPath } from "./remediationText";

const RULES_DIR = path.resolve(process.cwd(), "sast-rules");

function ruleFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return ruleFiles(full);
    return /\.ya?ml$/.test(name) ? [full] : [];
  });
}

type YamlRule = { id: string; cwes: string[]; severity: string | null; confidence: string | null; engineSeverity: string | null; message: boolean };

function parseRules(file: string): YamlRule[] {
  const rules: YamlRule[] = [];
  let current: YamlRule | null = null;
  let inCwe = false;
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const id = line.match(/^ {2}- id: ([\w-]+)\s*$/);
    if (id) {
      current = { id: id[1], cwes: [], severity: null, confidence: null, engineSeverity: null, message: false };
      rules.push(current);
      inCwe = false;
      continue;
    }
    if (!current) continue;
    if (/^ {4}message:/.test(line)) current.message = true;
    const engine = line.match(/^ {4}severity: (\w+)/);
    if (engine) current.engineSeverity = engine[1];
    const meta = line.match(/^ {6}(severity|confidence): (\w+)/);
    if (meta) current[meta[1] as "severity" | "confidence"] = meta[2];
    if (/^ {6}cwe:/.test(line)) {
      inCwe = true;
      continue;
    }
    if (inCwe) {
      const item = line.match(/^ {8}- "(CWE-\d+)/);
      if (item) current.cwes.push(item[1]);
      else inCwe = false;
    }
  }
  return rules;
}

const yamlRules = ruleFiles(RULES_DIR).flatMap(parseRules);

describe("sast rule pack ↔ catalogue", () => {
  it("finds the rule pack", () => {
    expect(yamlRules.length).toBeGreaterThanOrEqual(30);
  });

  it("has unique rule ids", () => {
    const ids = yamlRules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("catalogues exactly the rules that exist", () => {
    expect(yamlRules.map((r) => r.id).sort()).toEqual(Object.keys(SAST_RULE_CATEGORIES).sort());
  });

  it.each(yamlRules.map((r) => [r.id, r] as const))("%s has a message, CWE, confidence and product severity matching its category", (_id, rule) => {
    expect(rule.message).toBe(true);
    expect(rule.cwes.length).toBeGreaterThan(0);
    expect(["HIGH", "MEDIUM", "LOW"]).toContain(rule.confidence);
    expect(["critical", "high", "medium", "low"]).toContain(rule.severity);
    expect(["ERROR", "WARNING", "INFO"]).toContain(rule.engineSeverity);
    expect(sastCategoryForCwes(rule.cwes)).toBe(SAST_RULE_CATEGORIES[rule.id]);
  });
});

describe("catalogue wiring", () => {
  it.each(Object.keys(SAST_RULE_CATEGORIES))("sast.%s has compliance refs and a fix difficulty", (ruleId) => {
    const checkId = `sast.${ruleId}:0123456789abcdef`;
    expect(getComplianceRefs(checkId).length).toBeGreaterThan(0);
    expect(getFixDifficulty(checkId)).toBeDefined();
  });

  it("maps injection to OWASP A03 and deserialisation to A08", () => {
    const owasp = (id: string) => getComplianceRefs(`sast.${id}:x`).filter((r) => r.framework === "owasp-top-10").map((r) => r.control);
    expect(owasp("js-sql-injection")[0]).toMatch(/^A03/);
    expect(owasp("py-pickle-untrusted")[0]).toMatch(/^A08/);
    expect(owasp("php-laravel-debug-enabled")[0]).toMatch(/^A05/);
    expect(owasp("js-jwt-none-algorithm")).toEqual(expect.arrayContaining([expect.stringMatching(/^A02/)]));
  });

  it("has a label for every category", () => {
    for (const category of new Set(Object.values(SAST_CWE_CATEGORY))) expect(SAST_CATEGORY_LABELS[category]).toBeTruthy();
  });
});

describe("extractCweIds / sastCategoryForCwes", () => {
  it("extracts ids from engine metadata in any shape", () => {
    expect(extractCweIds(["CWE-89: Improper Neutralization ...", "cwe-89"])).toEqual(["CWE-89"]);
    expect(extractCweIds("CWE-78: OS Command Injection")).toEqual(["CWE-78"]);
    expect(extractCweIds(undefined)).toEqual([]);
    expect(extractCweIds([42, null])).toEqual([]);
  });
  it("returns null rather than guessing for an unknown CWE", () => {
    expect(sastCategoryForCwes(["CWE-1234"])).toBeNull();
  });
});

describe("sastRemediation", () => {
  it("gives language-specific examples", () => {
    expect(sastRemediation("sql-injection", "python")).toContain("cursor.execute(");
    expect(sastRemediation("sql-injection", "php")).toContain("$pdo->prepare");
    expect(sastRemediation("command-injection", "javascript")).toContain("execFile(");
  });
  it("falls back to the category text without an example for other languages, and to generic text with no category", () => {
    expect(sastRemediation("file-inclusion", "javascript")).toContain("allowed templates");
    expect(sastRemediation(null, "other")).toContain("nosemgrep");
  });
  it("detects the language from the file extension", () => {
    expect(sastLanguageForPath("src/a.TSX")).toBe("javascript");
    expect(sastLanguageForPath("app/views.py")).toBe("python");
    expect(sastLanguageForPath("public/index.php")).toBe("php");
    expect(sastLanguageForPath("Makefile")).toBe("other");
  });
});
