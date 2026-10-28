import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import PlanUpsell, { type Plan } from "./PlanUpsell";

describe("PlanUpsell", () => {
  it.each(["none", "basic", "pro", "agency", "tier_a"] as Plan[])("renders a label and a link for %s", (plan) => {
    render(<PlanUpsell plan={plan} />);
    expect(screen.getByRole("link")).toHaveAttribute("href");
    expect(screen.getByText(/^(No active plan|[A-Za-z ]+ plan)$/)).toBeInTheDocument();
  });

  it("doesn't throw for a Tier A subscriber, and only Tier A is called the top tier", () => {
    const { unmount } = render(<PlanUpsell plan="tier_a" />);
    expect(screen.getByText("Tier A plan")).toBeInTheDocument();
    expect(screen.getByText(/top tier/i)).toBeInTheDocument();
    unmount();
    render(<PlanUpsell plan="agency" />);
    expect(screen.queryByText(/top tier/i)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "See Tier A" })).toHaveAttribute("href", "/pricing");
  });
});
