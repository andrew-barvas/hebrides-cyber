// Reads commix's console output. Pure: no IO, so it is tested against output
// captured from a real commix run (fixtures/commix/, v4.2.dev190, run by
// .github/workflows/tool-integration.yml against tests/fixtures/test-app).
//
// What the capture established: with --batch commix prints, per parameter,
//   [warning] GET parameter 'q' does not seem to be injectable.
// and finishes with
//   [critical] All tested parameters do not appear to be injectable. ...
// A positive run has not been captured yet (it needs a deliberately
// command-injectable endpoint), so the "seems injectable / is vulnerable"
// wording below comes from commix's source and is kept alongside the negative
// markers rather than trusted alone: an unfinished run is never reported as
// clean (docs/SCANNER-CONVENTIONS.md).

const ANSI = /\u001b\[[0-9;]*m/g;

export type CommixInjection = { parameter: string; place: string };

/** Console text without colour codes or carriage-return progress noise. */
function clean(output: string): string {
  return output.replace(ANSI, "").replace(/\r/g, "\n");
}

// "The GET parameter 'q' seems injectable via ..." / "GET parameter 'q' is vulnerable ..."
const POSITIVE = /(?:^|\s)(?:(GET|POST|Cookie|User-Agent|Referer|Host|HTTP header)\s+)?parameter\s+'([^']+)'\s+(?:seems injectable|is vulnerable)/gim;
const NEGATIVE = /(GET|POST|Cookie|User-Agent|Referer|Host|HTTP header)\s+parameter\s+'([^']+)'\s+does not seem to be injectable/gi;
const FINISHED = /All tested parameters do not appear to be injectable|\bseems injectable\b|\bis vulnerable\b/i;
const NOTHING_TO_TEST = /No parameter\(s\) found for testing|does not contain any parameter|no usable links/i;
const UNREACHABLE = /unable to connect to the target|connection (?:refused|timed out|reset)|no route to host|name or service not known|Failed to establish a new connection/i;

/** Parameters commix reported as injectable, de-duplicated by place and name. */
export function parseInjections(output: string): CommixInjection[] {
  const seen = new Set<string>();
  const found: CommixInjection[] = [];
  for (const m of clean(output).matchAll(POSITIVE)) {
    const place = m[1] ?? "GET";
    const key = `${place}:${m[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    found.push({ parameter: m[2], place });
  }
  return found;
}

/** Parameters commix explicitly ruled out. */
export function parametersRuledOut(output: string): number {
  const names = new Set<string>();
  for (const m of clean(output).matchAll(NEGATIVE)) names.add(`${m[1]}:${m[2]}`);
  return names.size;
}

/**
 * Why a run with no injection says nothing about the target, or null when it
 * ran to a conclusion and tested something.
 */
export function runProblem(output: string): { kind: "error" | "not_applicable"; note: string } | null {
  const text = clean(output);
  if (UNREACHABLE.test(text)) return { kind: "error", note: "commix could not reach the target" };
  if (NOTHING_TO_TEST.test(text) && parametersRuledOut(text) === 0) return { kind: "not_applicable", note: "commix found no parameters to test" };
  if (!FINISHED.test(text)) return { kind: "error", note: "commix did not finish (no closing result line)" };
  if (parametersRuledOut(text) === 0 && parseInjections(text).length === 0) return { kind: "error", note: "commix finished without testing any parameter" };
  return null;
}
