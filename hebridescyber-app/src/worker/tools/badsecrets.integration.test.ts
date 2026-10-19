// Runs the real badsecrets (installed in its own virtualenv, as
// scheduled-scans.yml does) against a local server. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges.
//
// No key is committed: the cookie is signed at run time by badsecrets'
// virtualenv Python with flask_unsign (a badsecrets dependency), using an
// entry of badsecrets' own known-key list, so this checks the wrapper's
// flags and JSON parsing against what the pinned release really emits.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { execTool } from "../../lib/execTool";
import { runBadsecrets } from "./badsecrets";

const PYTHON = process.env.BADSECRETS_PYTHON ?? "/opt/badsecrets/bin/python";

// The list's whitespace is significant (its first entry has leading spaces),
// so take the first plain entry verbatim rather than stripping one.
const SIGN = `
import os, re, secrets, sys, badsecrets
from flask_unsign import session
path = os.path.join(os.path.dirname(badsecrets.__file__), "resources", "flask_secret_keys.txt")
known = next(l.rstrip("\\r\\n") for l in open(path, encoding="utf-8") if re.fullmatch(r"[A-Za-z0-9_-]{6,}", l.rstrip("\\r\\n")))
key = known if sys.argv[1] == "known" else secrets.token_hex(32)
print(session.sign({"user": "integration-test"}, secret=key))
`;

async function signedCookie(kind: "known" | "random"): Promise<string> {
  const { stdout } = await execTool(PYTHON, ["-c", SIGN, kind], { timeout: 60_000 });
  return stdout.trim();
}

function serve(cookie: string): Promise<Server> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html", "set-cookie": `session=${cookie}; Path=/; HttpOnly` });
    res.end("<!doctype html><title>Flask app</title><p>Hello</p>");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const urlOf = (s: Server) => `http://127.0.0.1:${(s.address() as AddressInfo).port}/`;

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("badsecrets against local servers", () => {
  let known: Server;
  let random: Server;

  beforeAll(async () => {
    known = await serve(await signedCookie("known"));
    random = await serve(await signedCookie("random"));
  }, 120_000);

  afterAll(() => {
    known?.close();
    random?.close();
  });

  it("reports a Flask session cookie signed with a known key", async () => {
    const result = await runBadsecrets(urlOf(known));
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.findings.map((f) => f.checkId)).toEqual(["badsecrets.known-secret:Flask_SignedCookies"]);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].metadata).toMatchObject({ locations: ["cookies"] });
  }, 200_000);

  it("stays silent on a cookie signed with a random key", async () => {
    const result = await runBadsecrets(urlOf(random));
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.findings).toEqual([]);
  }, 200_000);

  it("is an error, not clean, when the target is down", async () => {
    const down = await serve("x");
    const url = urlOf(down);
    await new Promise((r) => down.close(r));
    expect((await runBadsecrets(url)).status).toBe("error");
  }, 200_000);
});
