import { describe, expect, it } from "vitest";
import robots from "./robots";

describe("robots.txt", () => {
  it("keeps shared fix plan links out of search engines, alongside shared reports", () => {
    const rules = robots().rules;
    const list = (Array.isArray(rules) ? rules : [rules]).flatMap((r) => (Array.isArray(r.disallow) ? r.disallow : [r.disallow ?? ""]));
    expect(list).toContain("/plan");
    expect(list).toContain("/share");
  });
});
