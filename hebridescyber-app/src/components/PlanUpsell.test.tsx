import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import PlanUpsell, { type Plan } from "./PlanUpsell";

describe("PlanUpsell", () => {
  // Tier A had no entry, so the Overview threw on `undefined.label` for the
  // one plan that pays the most.
  it.each<[Plan, string, string]>([
    ["none", "View plans", "/pricing"],
    ["basic", "Upgrade to Pro", "/pricing"],
    ["pro", "Upgrade to Agency", "/pricing"],
    ["agency", "Compare plans", "/pricing"],
    ["tier_a", "Enquire", "/contact"],
  ])("renders %s with its next step", (plan, cta, href) => {
    render(<PlanUpsell plan={plan} />);
    expect(screen.getByRole("link", { name: cta })).toHaveAttribute("href", href);
  });

  it("calls Tier A, not Agency, the top tier", () => {
    const { unmount } = render(<PlanUpsell plan="tier_a" />);
    expect(screen.getByText("Tier A plan")).toBeInTheDocument();
    expect(screen.getByText(/top tier/)).toBeInTheDocument();
    unmount();
    render(<PlanUpsell plan="agency" />);
    expect(screen.queryByText(/top tier/)).not.toBeInTheDocument();
    expect(screen.getByText(/Tier A adds/)).toBeInTheDocument();
  });
});
