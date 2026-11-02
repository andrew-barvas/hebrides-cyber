// Customer-defined nuclei checks (Agency and Tier A): validation.
//
// A customer's template runs inside our scan worker, so nothing a template can
// say is trusted. This is an ALLOWLIST: anything not named here is refused,
// including nuclei features added in the future.
//
// What a template may do: send up to a few plain HTTP requests to the host
// being scanned and match on the response (status, words, regex, size,
// binary). What it may not: any other protocol (code, headless, javascript,
// network, dns, file, ssl, whois, websocket, workflow, flow), anything that
// sends traffic to another host (absolute URLs, a Host header other than the
// target's, out-of-band interactsh callbacks, redirects off-host), anything
// that reads the worker's files or runs a command (payload files, file/exec
// helpers, DSL expressions), request smuggling or racing (unsafe, race,
// pipeline), or fuzzing. Volume is capped so one template cannot hammer a site.
//
// Run-time flags in src/worker/tools/customNuclei.ts repeat the important
// limits (no interactsh, no code or headless, no local file access), so a
// validator gap would still not be enough to reach the worker.
import YAML from "yaml";

export const MAX_TEMPLATE_BYTES = 16 * 1024;
export const MAX_TEMPLATES_PER_OWNER = 20;
export const MAX_HTTP_BLOCKS = 5;
export const MAX_REQUESTS_PER_TEMPLATE = 60;
export const MAX_REDIRECTS_ALLOWED = 3;

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type CustomSeverity = (typeof SEVERITIES)[number];

const TOP_LEVEL_KEYS = new Set(["id", "info", "http"]);
// Legacy spelling of `http`; accepted and treated the same.
const LEGACY_HTTP_KEY = "requests";
const PROTOCOL_KEYS = new Set(["code", "headless", "javascript", "network", "tcp", "dns", "file", "ssl", "whois", "websocket", "workflows", "workflow", "flow", "http2", "self-contained", "variables", "signature"]);

const HTTP_BLOCK_KEYS = new Set(["id", "name", "method", "path", "raw", "headers", "body", "matchers", "matchers-condition", "extractors", "stop-at-first-match", "redirects", "max-redirects", "req-condition", "attack", "payloads"]);
const MATCHER_TYPES = new Set(["word", "regex", "status", "size", "binary"]);
const EXTRACTOR_TYPES = new Set(["regex", "kval", "json", "xpath"]);
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

const BASE_VARIABLES = new Set(["BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme", "FQDN", "RDN", "DN", "TLD", "SD"]);
// Pure string/number helpers. Nothing that touches the filesystem, runs a
// command, resolves a name, or calls out.
const SAFE_FUNCTIONS = new Set([
  "rand_int", "rand_text_alpha", "rand_text_alphanumeric", "rand_text_numeric", "randstr",
  "to_lower", "to_upper", "base64", "base64_decode", "url_encode", "url_decode", "md5", "sha1", "sha256", "concat", "trim", "len",
]);

export type TemplateCheck = { ok: true; id: string; name: string; severity: CustomSeverity; requests: number } | { ok: false; errors: string[] };

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

/** Every `{{ ... }}` in `text` must be a known variable, a payload name, or a call to a safe helper. */
function checkExpressions(text: string, where: string, payloadNames: Set<string>, errors: string[]) {
  for (const m of text.matchAll(/\{\{([\s\S]*?)\}\}/g)) {
    const expr = m[1].trim();
    if (BASE_VARIABLES.has(expr) || payloadNames.has(expr)) continue;
    const call = /^([A-Za-z_][A-Za-z0-9_]*)\(([^(){}]*)\)$/.exec(expr);
    if (call && SAFE_FUNCTIONS.has(call[1])) continue;
    errors.push(`${where}: "{{${expr}}}" is not allowed. Use {{BaseURL}}, {{Hostname}}, a payload name or a simple helper such as rand_int().`);
  }
}

/** True when a request path/line leaves the target: an absolute URL or a protocol-relative one. */
function leavesTarget(s: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(s) || s.startsWith("//");
}

function checkPath(path: unknown, where: string, errors: string[]) {
  if (typeof path !== "string") return errors.push(`${where}: each path must be text.`);
  if (!/^\{\{(BaseURL|RootURL)\}\}/.test(path.trim())) errors.push(`${where}: path "${path}" must start with {{BaseURL}} or {{RootURL}} so it stays on the scanned site.`);
  else if (/:\/\//.test(path.trim().replace(/^\{\{(BaseURL|RootURL)\}\}/, ""))) errors.push(`${where}: path "${path}" contains another address.`);
}

function checkHeaders(headers: unknown, where: string, errors: string[]) {
  if (headers === undefined) return;
  if (!isRecord(headers)) return void errors.push(`${where}: headers must be a map of names to values.`);
  for (const [k, v] of Object.entries(headers)) {
    if (typeof v !== "string" && typeof v !== "number") errors.push(`${where}: header "${k}" must be text.`);
    if (k.toLowerCase() === "host" && String(v).trim() !== "{{Hostname}}") errors.push(`${where}: a Host header other than {{Hostname}} would send the request to another site.`);
  }
}

function checkRaw(raw: unknown, where: string, errors: string[]) {
  if (typeof raw !== "string") return void errors.push(`${where}: each raw request must be text.`);
  const lines = raw.replace(/\r/g, "").split("\n");
  const first = lines.find((l) => l.trim() !== "") ?? "";
  const m = /^([A-Z]+)\s+(\S+)\s+HTTP\/[0-9.]+$/.exec(first.trim());
  if (!m) return void errors.push(`${where}: a raw request must start with a request line such as "GET /path HTTP/1.1".`);
  if (!METHODS.has(m[1])) errors.push(`${where}: method ${m[1]} is not allowed.`);
  if (leavesTarget(m[2])) errors.push(`${where}: the request line must be a path on the scanned site, not an address.`);
  for (const line of lines) {
    const h = /^host\s*:\s*(.*)$/i.exec(line.trim());
    if (h && h[1].trim() !== "{{Hostname}}") errors.push(`${where}: a Host header other than {{Hostname}} would send the request to another site.`);
  }
}

/** Number of payload combinations a block expands to, or an error. */
function payloadCombinations(payloads: unknown, where: string, attack: unknown, errors: string[]): { names: Set<string>; combos: number } {
  const names = new Set<string>();
  if (payloads === undefined) return { names, combos: 1 };
  if (!isRecord(payloads)) {
    errors.push(`${where}: payloads must be a map of names to lists.`);
    return { names, combos: 1 };
  }
  const sizes: number[] = [];
  for (const [k, v] of Object.entries(payloads)) {
    names.add(k);
    if (!Array.isArray(v)) {
      // A string is a file path on the worker.
      errors.push(`${where}: payload "${k}" must be an inline list. Files cannot be loaded.`);
      continue;
    }
    if (v.some((x) => typeof x !== "string" && typeof x !== "number")) errors.push(`${where}: payload "${k}" may only contain text or numbers.`);
    sizes.push(Math.max(v.length, 1));
  }
  if (attack !== undefined && !["batteringram", "pitchfork", "clusterbomb"].includes(String(attack))) errors.push(`${where}: unknown attack type "${String(attack)}".`);
  const combos = String(attack) === "clusterbomb" ? sizes.reduce((a, b) => a * b, 1) : Math.max(...sizes, 1);
  return { names, combos };
}

function checkMatchersAndExtractors(block: Record<string, unknown>, where: string, errors: string[]) {
  const matchers = asArray(block.matchers);
  if (matchers.length === 0) errors.push(`${where}: add at least one matcher, so a finding always comes with evidence.`);
  for (const m of matchers) {
    if (!isRecord(m)) {
      errors.push(`${where}: each matcher must be a map.`);
      continue;
    }
    if (!MATCHER_TYPES.has(String(m.type))) errors.push(`${where}: matcher type "${String(m.type)}" is not allowed. Use word, regex, status, size or binary.`);
  }
  for (const e of asArray(block.extractors)) {
    if (!isRecord(e) || !EXTRACTOR_TYPES.has(String(e.type))) errors.push(`${where}: extractor type "${isRecord(e) ? String(e.type) : "?"}" is not allowed. Use regex, kval, json or xpath.`);
  }
}

export function validateCustomTemplate(source: string): TemplateCheck {
  const errors: string[] = [];
  if (typeof source !== "string" || source.trim() === "") return { ok: false, errors: ["The template is empty."] };
  if (Buffer.byteLength(source, "utf8") > MAX_TEMPLATE_BYTES) return { ok: false, errors: [`The template is larger than ${MAX_TEMPLATE_BYTES / 1024} KB.`] };

  let doc: unknown;
  try {
    const docs = YAML.parseAllDocuments(source);
    if (docs.length !== 1) return { ok: false, errors: ["Put exactly one template in each entry."] };
    if (docs[0].errors.length > 0) return { ok: false, errors: [`The template is not valid YAML: ${docs[0].errors[0].message.split("\n")[0]}`] };
    doc = docs[0].toJS({ maxAliasCount: 20 });
  } catch (err) {
    return { ok: false, errors: [`The template is not valid YAML: ${(err as Error).message.split("\n")[0]}`] };
  }
  if (!isRecord(doc)) return { ok: false, errors: ["A template must be a YAML map with id, info and http."] };

  for (const key of Object.keys(doc)) {
    if (key === LEGACY_HTTP_KEY) continue;
    if (PROTOCOL_KEYS.has(key)) errors.push(`"${key}" is not available in custom checks. Only plain HTTP requests are allowed.`);
    else if (!TOP_LEVEL_KEYS.has(key)) errors.push(`"${key}" is not a supported template field.`);
  }

  const id = doc.id;
  if (typeof id !== "string" || !/^[a-z0-9][a-z0-9-]{2,63}$/.test(id)) errors.push("id must be 3 to 64 lowercase letters, digits or hyphens, for example internal-admin-exposed.");

  const info = doc.info;
  let name = "";
  let severity: CustomSeverity = "info";
  if (!isRecord(info)) errors.push("info is required, with a name and a severity.");
  else {
    if (typeof info.name !== "string" || info.name.trim() === "" || info.name.length > 200) errors.push("info.name is required (200 characters at most).");
    else name = info.name.trim();
    if (!SEVERITIES.includes(String(info.severity).toLowerCase() as CustomSeverity)) errors.push(`info.severity must be one of ${SEVERITIES.join(", ")}.`);
    else severity = String(info.severity).toLowerCase() as CustomSeverity;
  }

  const blocks = asArray(doc.http ?? doc[LEGACY_HTTP_KEY]);
  if (blocks.length === 0) errors.push("Add an http section with at least one request.");
  if (blocks.length > MAX_HTTP_BLOCKS) errors.push(`Use at most ${MAX_HTTP_BLOCKS} http blocks.`);

  let requests = 0;
  blocks.slice(0, MAX_HTTP_BLOCKS).forEach((b, i) => {
    const where = `http[${i}]`;
    if (!isRecord(b)) return void errors.push(`${where} must be a map.`);
    for (const key of Object.keys(b)) {
      if (!HTTP_BLOCK_KEYS.has(key)) errors.push(`${where}: "${key}" is not allowed.${["unsafe", "race", "race_count", "pipeline", "fuzzing", "digest-username", "host-redirects", "cookie-reuse"].includes(key) ? " It could send unusual or repeated traffic." : ""}`);
    }
    if (b.method !== undefined && !METHODS.has(String(b.method).toUpperCase())) errors.push(`${where}: method "${String(b.method)}" is not allowed.`);
    const paths = asArray(b.path);
    const raws = asArray(b.raw);
    if (paths.length === 0 && raws.length === 0) errors.push(`${where}: add a path or a raw request.`);
    if (paths.length > 0 && raws.length > 0) errors.push(`${where}: use either path or raw, not both.`);
    paths.forEach((p) => checkPath(p, where, errors));
    raws.forEach((r) => checkRaw(r, where, errors));
    checkHeaders(b.headers, where, errors);
    if (b.body !== undefined && typeof b.body !== "string") errors.push(`${where}: body must be text.`);
    if (b["max-redirects"] !== undefined && !(Number.isInteger(b["max-redirects"]) && (b["max-redirects"] as number) >= 0 && (b["max-redirects"] as number) <= MAX_REDIRECTS_ALLOWED)) {
      errors.push(`${where}: max-redirects must be a whole number from 0 to ${MAX_REDIRECTS_ALLOWED}.`);
    }
    const { names, combos } = payloadCombinations(b.payloads, where, b.attack, errors);
    checkMatchersAndExtractors(b, where, errors);
    // Expressions are checked on everything the block sends, and nowhere else:
    // matcher words legitimately contain braces.
    const sent = [...paths, ...raws, b.body, ...(isRecord(b.headers) ? Object.values(b.headers) : [])].filter((x): x is string => typeof x === "string");
    sent.forEach((s) => checkExpressions(s, where, names, errors));
    requests += Math.max(paths.length + raws.length, 1) * combos;
  });
  if (requests > MAX_REQUESTS_PER_TEMPLATE) errors.push(`This template would send ${requests} requests per scan. The limit is ${MAX_REQUESTS_PER_TEMPLATE}.`);

  // Belt and braces, on the raw text: an out-of-band callback or file include
  // anywhere in the document, wherever a future nuclei version would read it.
  if (/interactsh|oast\./i.test(source)) errors.push("Out-of-band (interactsh) callbacks are not available in custom checks.");

  return errors.length > 0 ? { ok: false, errors: [...new Set(errors)] } : { ok: true, id: id as string, name, severity, requests };
}
