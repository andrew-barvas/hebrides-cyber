// Arjun integration — HTTP parameter discovery.
//
// Arjun discovers hidden GET/POST parameters by analyzing responses
// to parameter-injection requests. Useful for finding undocumented
// API parameters that may bypass validation. When the binary is absent,
// returns { status: "not_configured" } so the worker continues gracefully.

import { execTool } from "../../lib/execTool";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const execFileAsync = execTool;

const ARJUN_TIMEOUT_MS = 180_000;

export type ArjunParameter = {
  url: string;
  method: string;
  params: string[];
};

export type ArjunResult =
  | { status: "completed"; parameters: ArjunParameter[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

export async function runArjun(targetUrl: string): Promise<ArjunResult> {
  const outFile = join(tmpdir(), `arjun-${Date.now()}.json`);
  try {
    await execFileAsync(
      "arjun",
      [
        "-u", targetUrl,
        "-oJ", outFile,
        "-t", "5",
        "--stable",
      ],
      { timeout: ARJUN_TIMEOUT_MS }
    );

    let parsed: ArjunParameter[] = [];
    try {
      const raw = await readFile(outFile, "utf8");
      // arjun's -oJ output is a JSON object keyed by URL, each value holding the
      // discovered params plus the method and headers — it is NOT an array (see
      // arjun's core/exporter.py `json_export`). Parsing it as an array made
      // `.filter` throw, which this function then swallowed, so a real run that
      // found parameters still returned an empty list on every scan.
      const data = JSON.parse(raw) as Record<
        string,
        { method?: string; params?: string[]; headers?: Record<string, string> }
      >;
      parsed = Object.entries(data)
        .filter(([url, entry]) => url && Array.isArray(entry?.params) && entry.params!.length > 0)
        .map(([url, entry]) => ({
          url,
          method: entry.method ?? "GET",
          params: entry.params!,
        }));
    } catch {
      // Output file missing or malformed — return empty
    }

    return { status: "completed", parameters: parsed };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured" };
    }
    return {
      status: "error",
      note: `arjun exited with error: ${error.message}`,
    };
  } finally {
    rm(outFile, { force: true }).catch(() => undefined);
  }
}
