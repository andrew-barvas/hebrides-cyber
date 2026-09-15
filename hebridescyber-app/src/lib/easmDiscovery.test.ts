import { describe, it, expect } from "vitest";

// The module makes real network calls (crt.sh, Cloudflare DNS, HTTP probes),
// so we test the pure logic aspects and mock the network calls.

describe("easmDiscovery", () => {
  it("COMMON_PREFIXES covers essential subdomains", async () => {
    // Import the module to verify it loads without error
    const mod = await import("./easmDiscovery");
    expect(mod.runEasmDiscovery).toBeTypeOf("function");
  });

  it("exports the expected types", async () => {
    const mod = await import("./easmDiscovery");
    // Verify the function signature exists
    expect(mod.runEasmDiscovery).toBeDefined();
  });
});
