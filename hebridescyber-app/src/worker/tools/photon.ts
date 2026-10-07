// Photon integration — OSINT URL/email/social media harvesting.
//
// Photon crawls a target and extracts URLs, emails, social media links,
// files, and JavaScript endpoints. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.

import { execTool } from "../../lib/execTool";
import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const execFileAsync = execTool;

const PHOTON_TIMEOUT_MS = 180_000;

export type PhotonAsset = {
  type: "url" | "email" | "social" | "file" | "js-endpoint";
  value: string;
};

export type PhotonResult =
  | { status: "completed"; assets: PhotonAsset[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

function parsePhotonOutput(dir: string): Promise<PhotonAsset[]> {
  const assets: PhotonAsset[] = [];

  async function readLines(file: string, type: PhotonAsset["type"]): Promise<void> {
    try {
      const content = await readFile(join(dir, file), "utf8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed) assets.push({ type, value: trimmed });
      }
    } catch {
      // File may not exist if nothing was found for that category
    }
  }

  return Promise.all([
    readLines("internal.txt", "url"),
    readLines("external.txt", "url"),
    readLines("scripts.txt", "js-endpoint"),
    readLines("fuzzable.txt", "url"),
    readLines("emails.txt", "email"),
  ]).then(() => assets);
}

export async function runPhoton(targetUrl: string): Promise<PhotonResult> {
  let outDir: string | undefined;
  try {
    outDir = await mkdtemp(join(tmpdir(), "photon-"));

    await execFileAsync(
      "photon",
      ["-u", targetUrl, "-o", outDir, "-l", "3", "--keys", "--dns", "-t", "5"],
      { timeout: PHOTON_TIMEOUT_MS }
    );

    const assets = await parsePhotonOutput(outDir);
    return { status: "completed", assets };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured" };
    }
    return {
      status: "error",
      note: `photon exited with error: ${error.message}`,
    };
  } finally {
    if (outDir) {
      rm(outDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}
