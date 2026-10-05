// Loading and validating bench/expectations/*.json.
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { moduleOf, type Expectation, type KnownIssue } from "./scoring";

function stringList(value: unknown, field: string, file: string, scope: readonly string[]): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string" || v.length === 0)) {
    throw new Error(`${file}: "${field}" must be an array of non-empty strings`);
  }
  for (const pattern of value as string[]) {
    if (pattern.startsWith("*")) throw new Error(`${file}: "${pattern}" in "${field}" needs a "<module>." prefix before the wildcard`);
    if (!scope.includes(moduleOf(pattern))) {
      throw new Error(`${file}: "${pattern}" in "${field}" is not in a module the benchmark drives (${scope.join(", ")})`);
    }
  }
  return value as string[];
}

function knownIssues(value: unknown, file: string, scope: readonly string[]): KnownIssue[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${file}: "knownIssues" must be an array`);
  return value.map((raw, i) => {
    const item = raw as Partial<KnownIssue> | null;
    if (!item || typeof item !== "object") throw new Error(`${file}: knownIssues[${i}] must be an object`);
    if (item.kind !== "miss" && item.kind !== "false-positive") {
      throw new Error(`${file}: knownIssues[${i}].kind must be "miss" or "false-positive"`);
    }
    if (typeof item.note !== "string" || item.note.length === 0) {
      throw new Error(`${file}: knownIssues[${i}].note must explain the defect`);
    }
    const [checkId] = stringList([item.checkId], `knownIssues[${i}].checkId`, file, scope);
    return { checkId, kind: item.kind, note: item.note };
  });
}

/** Validates one parsed expectation file. Throws a descriptive error on any problem. */
export function parseExpectation(raw: unknown, file: string, scope: readonly string[]): Expectation {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${file}: must be a JSON object`);
  const obj = raw as Record<string, unknown>;
  const expectedId = path.basename(file, ".json");
  if (obj.target !== expectedId) throw new Error(`${file}: "target" must equal the file name ("${expectedId}")`);
  if (typeof obj.description !== "string" || obj.description.length === 0) {
    throw new Error(`${file}: "description" is required`);
  }

  const mustFind = stringList(obj.mustFind, "mustFind", file, scope);
  const mustNotFind = stringList(obj.mustNotFind, "mustNotFind", file, scope);
  const optional = stringList(obj.optional, "optional", file, scope);
  const both = mustFind.filter((p) => mustNotFind.includes(p));
  if (both.length > 0) throw new Error(`${file}: ${both.join(", ")} appears in both mustFind and mustNotFind`);

  return {
    target: expectedId,
    description: obj.description,
    mustFind,
    mustNotFind,
    optional,
    knownIssues: knownIssues(obj.knownIssues, file, scope),
  };
}

/** Loads every expectation in `dir`, keyed by target id. */
export function loadExpectations(dir: string, scope: readonly string[]): Map<string, Expectation> {
  const out = new Map<string, Expectation>();
  const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  for (const name of files) {
    const file = path.join(dir, name);
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch (err) {
      throw new Error(`${file}: invalid JSON (${(err as Error).message})`);
    }
    const expectation = parseExpectation(raw, file, scope);
    out.set(expectation.target, expectation);
  }
  return out;
}
