// Arjun integration — HTTP parameter discovery.
//
// Arjun discovers hidden GET/POST parameters by analyzing responses
// to parameter-injection requests. Useful for finding undocumented
// API parameters that may bypass validation. When the binary is absent,
// returns { status: "not_configured" } so the worker continues gracefully.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const execFileAsync = promisify(execFile);

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
      const data = JSON.parse(raw) as Array<{
        url?: string;
        method?: string;
        params?: string[];
      }>;
      parsed = data
        .filter((entry) => entry.url && entry.params && entry.params.length > 0)
        .map((entry) => ({
          url: entry.url!,
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
