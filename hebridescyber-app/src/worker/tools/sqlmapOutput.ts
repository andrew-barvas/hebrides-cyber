// Reads the output of a sqlmap run (console text, per-host log, results CSV)
// into a plain list of reported injection points. Pure functions only, tested
// against output captured from a real sqlmap 1.10.9 run (fixtures/sqlmap/).
//
// Layout of what sqlmap writes, as observed:
// - console and <output-dir>/<host>/log: a block per affected parameter,
//     sqlmap identified the following injection point(s) with a total of N HTTP(s) requests:
//     ---
//     Parameter: id (GET)
//         Type: boolean-based blind
//     ---
//   then a `back-end DBMS: <name>` line. No timestamp prefix on these lines.
// - <output-dir>/results-<timestamp>.csv: `Target URL,Place,Parameter,Technique(s),Note(s)`.

export type InjectionPoint = {
  parameter: string;
  place: string;
  techniques: string[];
  dbms: string | null;
  url: string | null;
};

// Terminal control sequences sqlmap prints even when stdout is not a TTY.
const TERMINAL_CODES = /\x1b(?:\[[0-9;?]*[A-Za-z]|[()][0-9A-Za-z])/g;

export function stripTerminalCodes(text: string): string {
  return text.replace(TERMINAL_CODES, "");
}

const TECHNIQUE_LETTERS: Record<string, string> = {
  B: "boolean-based blind",
  E: "error-based",
  U: "UNION query",
  S: "stacked queries",
  T: "time-based blind",
  Q: "inline queries",
};

const BLOCK = /sqlmap identified the following injection point\(s\)[^\n]*\n---\n([\s\S]*?)\n---/g;
const PARAMETER = /^Parameter: (.+) \(([^()]+)\)\s*$/gm;
const TECHNIQUE = /^\s+Type: (.+?)\s*$/gm;
const DBMS = /^back-end DBMS: (.+?)\s*$/m;

/** Injection points named in console output or a per-host log file. */
export function parseReportedBlocks(text: string): InjectionPoint[] {
  const clean = stripTerminalCodes(text);
  const points: InjectionPoint[] = [];
  for (const block of clean.matchAll(BLOCK)) {
    const body = block[1];
    const rest = clean.slice((block.index as number) + block[0].length);
    const nextBlock = rest.search(/sqlmap identified the following injection point/);
    const dbms = (nextBlock === -1 ? rest : rest.slice(0, nextBlock)).match(DBMS)?.[1] ?? null;

    const params = [...body.matchAll(PARAMETER)];
    params.forEach((p, i) => {
      const start = (p.index as number) + p[0].length;
      const section = body.slice(start, params[i + 1]?.index ?? body.length);
      points.push({
        parameter: p[1].trim(),
        place: p[2].trim(),
        techniques: [...section.matchAll(TECHNIQUE)].map((t) => t[1]),
        dbms,
        url: null,
      });
    });
  }
  return points;
}

/** Splits one CSV line; commas inside double quotes stay in the field. */
function splitCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && quoted && line[i + 1] === '"') {
      current += '"';
      i++;
    } else if (ch === '"') {
      quoted = !quoted;
    } else if (ch === "," && !quoted) {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

/** Rows of a results CSV (header skipped): one per affected parameter. */
export function parseResultsCsv(csv: string): InjectionPoint[] {
  const points: InjectionPoint[] = [];
  for (const line of csv.split(/\r?\n/).slice(1)) {
    if (!line.trim()) continue;
    const [url = "", place = "", parameter = "", letters = ""] = splitCsvLine(line);
    if (!place.trim() || !parameter.trim()) continue;
    points.push({
      parameter: parameter.trim(),
      place: place.trim(),
      techniques: [...letters.trim()].map((l) => TECHNIQUE_LETTERS[l]).filter((t): t is string => !!t),
      dbms: null,
      url: url.trim() || null,
    });
  }
  return points;
}

/** One entry per place + parameter, merging techniques, DBMS and URL across sources. */
export function mergeInjectionPoints(sources: InjectionPoint[][]): InjectionPoint[] {
  const byKey = new Map<string, InjectionPoint>();
  for (const point of sources.flat()) {
    const key = `${point.place.toUpperCase()}|${point.parameter}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...point, techniques: [...point.techniques] });
      continue;
    }
    for (const t of point.techniques) if (!existing.techniques.includes(t)) existing.techniques.push(t);
    existing.dbms ??= point.dbms;
    existing.url ??= point.url;
  }
  return [...byKey.values()];
}

/** Number of distinct parameters sqlmap probed, from its console output. */
export function countParametersTested(stdout: string): number {
  const seen = new Set<string>();
  for (const m of stripTerminalCodes(stdout).matchAll(/testing if (.+?) parameter '(.+?)' is dynamic/g)) {
    seen.add(`${m[1]}|${m[2]}`);
  }
  return seen.size;
}

/** Why a run's console output can't be trusted as a complete test, or null. */
export function runProblem(stdout: string): string | null {
  const text = stripTerminalCodes(stdout);
  const connection = text.match(/\[CRITICAL\] (unable to connect[^\n]*)/);
  if (connection) return connection[1].trim();
  if (!text.includes("[*] ending @")) return "sqlmap stopped before it finished";
  return null;
}
