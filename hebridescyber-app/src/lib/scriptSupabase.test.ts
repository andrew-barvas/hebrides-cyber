import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createScriptSupabase } from "./scriptSupabase";

describe("createScriptSupabase", () => {
  let exit: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exits 1 before building a client when the URL is missing", () => {
    expect(() => createScriptSupabase({ SUPABASE_SERVICE_ROLE_KEY: "k" })).toThrow("exit 1");
    expect(exit).toHaveBeenCalledWith(1);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("SUPABASE_URL"));
  });

  it("exits 1 when the service role key is missing", () => {
    expect(() => createScriptSupabase({ SUPABASE_URL: "https://example-project.supabase.co" })).toThrow("exit 1");
  });

  it("returns a client when both are set", () => {
    const client = createScriptSupabase({ SUPABASE_URL: "https://example-project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "k" });
    expect(typeof client.from).toBe("function");
    expect(exit).not.toHaveBeenCalled();
  });
});
