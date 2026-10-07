// @vitest-environment node
import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { execTool } from "./execTool";

// A child that, like nuclei and gospider, reads stdin to the end before working.
const READS_STDIN = ["-e", "let n = 0; process.stdin.on('data', (d) => (n += d.length)); process.stdin.on('end', () => console.log('stdin closed after ' + n + ' bytes'))"];

describe("execTool", () => {
  it("closes the child's stdin, so a tool that reads it to the end finishes", async () => {
    const { stdout } = await execTool(process.execPath, READS_STDIN, { timeout: 10_000 });
    expect(stdout.trim()).toBe("stdin closed after 0 bytes");
  });

  it("is needed: plain execFile leaves stdin open and the same child never finishes", async () => {
    await expect(promisify(execFile)(process.execPath, READS_STDIN, { timeout: 1_500 })).rejects.toMatchObject({ killed: true });
  });

  it("passes arguments, options and failures through unchanged", async () => {
    const { stdout } = await execTool(process.execPath, ["-e", "console.log(process.argv.slice(1).join(','), process.env.X)", "a", "b"], { env: { ...process.env, X: "y" } });
    expect(stdout.trim()).toBe("a,b y");
    await expect(execTool(process.execPath, ["-e", "process.exit(3)"])).rejects.toMatchObject({ code: 3 });
    await expect(execTool("/nonexistent/tool", [])).rejects.toMatchObject({ code: "ENOENT" });
  });
});
