// A real PostgREST in front of a test database, reached through supabase-js
// the way production code reaches Supabase. For tests that need to confirm
// PostgREST accepts a module's query shapes, which fakes can't.
//
// Needs the PostgREST binary: set POSTGREST_BIN to its path (the db-tests
// workflow downloads the official release, pinned by checksum).
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { TestDb } from "./harness";

// supabase-js builds its realtime client eagerly and throws on Node 20, which
// has no native WebSocket (Node 22+ does). These tests never use realtime.
if (!("WebSocket" in globalThis)) (globalThis as Record<string, unknown>).WebSocket = class {};

export const POSTGREST_BIN = process.env.POSTGREST_BIN;

const SECRET = "test-secret-test-secret-test-secret-1234";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function jwt(role: string): string {
  const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ role, exp: Math.floor(Date.now() / 1000) + 3600 })}`;
  return `${head}.${createHmac("sha256", SECRET).update(head).digest("base64url")}`;
}

export interface Postgrest {
  /** A service-role supabase-js client, as server code uses. */
  client: SupabaseClient;
  stop(): void;
}

/** Starts PostgREST on `port` and a /rest/v1 proxy on `port + 1`. Use a distinct port per test file. */
export async function startPostgrest(db: TestDb, port: number): Promise<Postgrest> {
  const apiPort = port + 1;
  const dir = mkdtempSync(path.join(tmpdir(), "postgrest-"));
  const conf = path.join(dir, "postgrest.conf");
  writeFileSync(conf, [`db-uri = "${db.url}"`, `db-schemas = "public"`, `db-anon-role = "anon"`, `jwt-secret = "${SECRET}"`, `server-port = ${port}`, `server-host = "127.0.0.1"`, ""].join("\n"));
  const server = spawn(POSTGREST_BIN as string, [conf], { stdio: "ignore" });
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/`, { headers: { apikey: jwt("service_role") } })).status < 500) break;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  // supabase-js addresses PostgREST at /rest/v1 (as Supabase's gateway does); PostgREST serves at the root.
  const proxy = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      const upstream = await fetch(`http://127.0.0.1:${port}${(req.url ?? "").replace(/^\/rest\/v1/, "")}`, {
        method: req.method,
        headers: Object.fromEntries(Object.entries(req.headers).filter(([k]) => k !== "host" && k !== "content-length") as [string, string][]),
        body: ["GET", "HEAD"].includes(req.method ?? "GET") ? undefined : Buffer.concat(chunks),
      });
      res.writeHead(upstream.status, Object.fromEntries(upstream.headers.entries()));
      res.end(Buffer.from(await upstream.arrayBuffer()));
    });
  }).listen(apiPort, "127.0.0.1");
  const client = createClient(`http://127.0.0.1:${apiPort}`, jwt("service_role"), { auth: { persistSession: false } });
  return {
    client,
    stop() {
      server.kill();
      proxy.close();
    },
  };
}
