import { describe, it, expect } from "vitest";
import { MAX_REQUESTS_PER_TEMPLATE, MAX_TEMPLATE_BYTES, validateCustomTemplate } from "./customNucleiTemplates";

const base = (http: string, extra = "") => `id: internal-admin-exposed
info:
  name: Internal admin reachable
  severity: HIGH
${extra}${http}`;

const GOOD_HTTP = `http:
  - method: GET
    path:
      - "{{BaseURL}}/internal-admin"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Admin console"
`;

const problems = (yaml: string) => {
  const r = validateCustomTemplate(yaml);
  return r.ok ? [] : r.errors;
};

describe("validateCustomTemplate: accepts", () => {
  it("a plain HTTP template, normalising the severity", () => {
    expect(validateCustomTemplate(base(GOOD_HTTP))).toEqual({ ok: true, id: "internal-admin-exposed", name: "Internal admin reachable", severity: "high", requests: 1 });
  });

  it("raw requests to the target host, the legacy `requests` key, payload lists and safe helpers", () => {
    const yaml = base(`requests:
  - raw:
      - |
        GET /debug?x={{rand_int(1,9)}}&y={{word}} HTTP/1.1
        Host: {{Hostname}}
    payloads:
      word: [one, two, three]
    matchers:
      - type: regex
        regex: ["stack trace"]
`);
    const r = validateCustomTemplate(yaml);
    expect(r.ok, JSON.stringify(r)).toBe(true);
    expect(r.ok && r.requests).toBe(3);
  });
});

describe("validateCustomTemplate: refuses every other protocol", () => {
  it.each(["code", "headless", "javascript", "network", "tcp", "dns", "file", "ssl", "whois", "websocket", "workflows", "flow", "variables", "self-contained"])("%s", (key) => {
    const out = problems(base(GOOD_HTTP, `${key}: ["x"]\n`));
    expect(out.join(" ")).toContain(`"${key}" is not available`);
  });

  it("and unknown top-level fields", () => {
    expect(problems(base(GOOD_HTTP, "totally-new: 1\n")).join(" ")).toContain("not a supported template field");
  });
});

describe("validateCustomTemplate: keeps requests on the scanned site", () => {
  it.each([
    ["an absolute path", `path: ["http://evil.example/x"]`],
    ["a protocol-relative path", `path: ["//evil.example/x"]`],
    ["a bare path with no BaseURL", `path: ["/admin"]`],
    ["another address after BaseURL", `path: ["{{BaseURL}}/r?u=http://evil.example"]`],
    ["a Hostname-less Host header", `path: ["{{BaseURL}}/"]\n    headers:\n      Host: evil.example`],
  ])("%s", (_name, req) => {
    const yaml = base(`http:\n  - ${req}\n    matchers:\n      - type: status\n        status: [200]\n`);
    expect(problems(yaml).length).toBeGreaterThan(0);
  });

  it.each([
    ["an absolute request line", "GET http://evil.example/ HTTP/1.1\n        Host: {{Hostname}}"],
    ["a different Host header", "GET / HTTP/1.1\n        Host: evil.example"],
    ["a Host header with a port swap", "GET / HTTP/1.1\n        host: {{Hostname}}.evil.example"],
    ["a malformed request line", "this is not http"],
    ["a disallowed method", "CONNECT / HTTP/1.1\n        Host: {{Hostname}}"],
  ])("raw: %s", (_name, rawReq) => {
    const yaml = base(`http:\n  - raw:\n      - |\n        ${rawReq}\n    matchers:\n      - type: status\n        status: [200]\n`);
    expect(problems(yaml).length).toBeGreaterThan(0);
  });

  it("refuses interactsh anywhere, including the callback placeholder", () => {
    const yaml = base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/?u={{interactsh-url}}"]\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [http]\n`);
    expect(problems(yaml).join(" ")).toMatch(/interactsh|not allowed/);
  });
});

describe("validateCustomTemplate: nothing that reads files or runs code", () => {
  it.each([
    ["file helper", '{{file("/etc/passwd")}}'],
    ["exec helper", '{{exec("id")}}'],
    ["env-style variable", "{{env}}"],
    ["nested call", "{{base64(rand_int(1,2))}}"],
    ["template-path variable", "{{template-path}}"],
    ["DNS resolve helper", '{{resolve("evil.example")}}'],
  ])("%s", (_name, expr) => {
    const yaml = base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/?q=${expr.replace(/"/g, "'")}"]\n    matchers:\n      - type: status\n        status: [200]\n`);
    expect(problems(yaml).join(" ")).toContain("is not allowed");
  });

  it("payload files (a string where a list belongs)", () => {
    const yaml = base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/{{p}}"]\n    payloads:\n      p: /usr/share/wordlists/rockyou.txt\n    matchers:\n      - type: status\n        status: [200]\n`);
    expect(problems(yaml).join(" ")).toContain("inline list");
  });

  it("DSL matchers, which can call arbitrary helper functions", () => {
    const yaml = base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/"]\n    matchers:\n      - type: dsl\n        dsl: ["contains(body, 'x')"]\n`);
    expect(problems(yaml).join(" ")).toContain('matcher type "dsl"');
  });

  it("DSL extractors", () => {
    const yaml = base(GOOD_HTTP.replace("matchers:", "extractors:\n      - type: dsl\n        dsl: ['x']\n    matchers:"));
    expect(problems(yaml).join(" ")).toContain('extractor type "dsl"');
  });
});

describe("validateCustomTemplate: no unusual traffic or volume", () => {
  it.each(["unsafe", "race", "pipeline", "fuzzing", "host-redirects", "cookie-reuse", "digest-username"])("%s is refused", (key) => {
    const yaml = base(GOOD_HTTP.replace("    matchers:", `    ${key}: true\n    matchers:`));
    expect(problems(yaml).join(" ")).toContain(`"${key}" is not allowed`);
  });

  it("caps redirects", () => {
    expect(problems(base(GOOD_HTTP.replace("    matchers:", "    redirects: true\n    max-redirects: 50\n    matchers:"))).join(" ")).toContain("max-redirects");
  });

  it("caps requests per scan, counting clusterbomb payload combinations", () => {
    const nums = (n: number) => `[${Array.from({ length: n }, (_, i) => i).join(", ")}]`;
    const yaml = base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/{{a}}/{{b}}"]\n    attack: clusterbomb\n    payloads:\n      a: ${nums(10)}\n      b: ${nums(10)}\n    matchers:\n      - type: status\n        status: [200]\n`);
    expect(problems(yaml).join(" ")).toContain(`The limit is ${MAX_REQUESTS_PER_TEMPLATE}`);
  });

  it("limits the number of http blocks", () => {
    const block = `  - method: GET\n    path: ["{{BaseURL}}/"]\n    matchers:\n      - type: status\n        status: [200]\n`;
    expect(problems(base(`http:\n${block.repeat(6)}`)).join(" ")).toContain("at most");
  });

  it("requires a matcher, so every finding has evidence", () => {
    expect(problems(base(`http:\n  - method: GET\n    path: ["{{BaseURL}}/"]\n`)).join(" ")).toContain("at least one matcher");
  });
});

describe("validateCustomTemplate: the document itself", () => {
  it("rejects bad ids, missing info and severity", () => {
    expect(problems(GOOD_HTTP).length).toBeGreaterThan(0);
    expect(problems(base(GOOD_HTTP).replace("internal-admin-exposed", "../../etc/passwd")).join(" ")).toContain("id must be");
    expect(problems(base(GOOD_HTTP).replace("severity: HIGH", "severity: apocalyptic")).join(" ")).toContain("info.severity");
  });

  it("rejects empty, oversized, multi-document and non-YAML input", () => {
    expect(problems("")).toEqual(["The template is empty."]);
    expect(problems("x".repeat(MAX_TEMPLATE_BYTES + 1))[0]).toContain("larger than");
    expect(problems(base(GOOD_HTTP) + "\n---\n" + base(GOOD_HTTP))[0]).toContain("exactly one");
    expect(problems("id: [unclosed")[0]).toContain("not valid YAML");
    expect(problems("- just\n- a list")[0]).toContain("must be a YAML map");
  });

  it("survives alias bombs without hanging", () => {
    const yaml = ["a: &a [x,x,x,x,x,x,x,x,x]", ...Array.from({ length: 12 }, (_, i) => `b${i}: &b${i} [${(i === 0 ? ["*a"] : [`*b${i - 1}`]).concat(i === 0 ? ["*a"] : [`*b${i - 1}`]).join(",")}]`)].join("\n");
    const start = Date.now();
    expect(validateCustomTemplate(yaml).ok).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it("never throws, whatever it is given", () => {
    for (const v of [null, undefined, 5, {}, [], "\u0000", "id: !!js/function 'x'"]) expect(() => validateCustomTemplate(v as never)).not.toThrow();
  });
});
