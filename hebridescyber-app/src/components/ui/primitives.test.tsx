import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import Link from "next/link";
import { Button } from "./button";
import { Alert } from "./alert";
import { CardTitle } from "./card";
import { SegmentedControl } from "./segmented-control";
import { StatCard } from "./stat-card";
import { EmptyState } from "./empty-state";

describe("Button", () => {
  it("defaults to type=button so it never submits a surrounding form by accident", () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <Button>Cancel</Button>
      </form>
    );
    const button = screen.getByRole("button", { name: "Cancel" });
    expect(button).toHaveAttribute("type", "button");
    fireEvent.click(button);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("still submits when explicitly asked to", () => {
    render(<Button type="submit">Save</Button>);
    expect(screen.getByRole("button", { name: "Save" })).toHaveAttribute("type", "submit");
  });

  it("asChild renders the child element (a link stays a link) with button styling and no type attribute", () => {
    render(
      <Button asChild variant="secondary">
        <Link href="/pricing">Compare plans</Link>
      </Button>
    );
    const link = screen.getByRole("link", { name: "Compare plans" });
    expect(link).toHaveAttribute("href", "/pricing");
    expect(link).not.toHaveAttribute("type");
    expect(link.className).toContain("border-cyberborder");
  });

  it("lets a className override a conflicting default utility", () => {
    render(<Button className="h-12">Tall</Button>);
    const cls = screen.getByRole("button", { name: "Tall" }).className;
    expect(cls).toContain("h-12");
    expect(cls).not.toContain("h-10");
  });
});

describe("Alert", () => {
  it("announces danger assertively and everything else politely", () => {
    const { rerender } = render(<Alert variant="danger">Payment failed</Alert>);
    expect(screen.getByRole("alert")).toHaveTextContent("Payment failed");

    rerender(<Alert variant="success">Saved</Alert>);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Saved");
  });

  it("renders a title alongside the body", () => {
    render(
      <Alert variant="warning" title="Checkout cancelled">
        Your plan hasn&apos;t changed.
      </Alert>
    );
    expect(screen.getByText("Checkout cancelled")).toBeInTheDocument();
    expect(screen.getByText(/Your plan hasn't changed/)).toBeInTheDocument();
  });
});

describe("CardTitle", () => {
  it("keeps the brand's // prefix out of the accessible heading name", () => {
    render(<CardTitle>slack alerts</CardTitle>);
    const heading = screen.getByRole("heading", { level: 2 });
    expect(heading).toHaveTextContent("// slack alerts");
    expect(heading.querySelector('[aria-hidden="true"]')).toHaveTextContent("//");
  });

  it("can render at h3", () => {
    render(<CardTitle as="h3">latest findings</CardTitle>);
    expect(screen.getByRole("heading", { level: 3 })).toBeInTheDocument();
  });
});

describe("SegmentedControl", () => {
  const options = [
    { value: "all", label: "All (3)" },
    { value: "new", label: "New (1)" },
    { value: "fixed", label: "Fixed (0)" },
  ] as const;

  it("exposes the selected option via aria-pressed, not colour alone", () => {
    render(<SegmentedControl aria-label="Filter findings" value="new" onChange={() => {}} options={options} />);
    expect(screen.getByRole("group", { name: "Filter findings" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New (1)" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "All (3)" })).toHaveAttribute("aria-pressed", "false");
  });

  it("reports the chosen value", () => {
    const onChange = vi.fn();
    render(<SegmentedControl aria-label="Filter findings" value="all" onChange={onChange} options={options} />);
    fireEvent.click(screen.getByRole("button", { name: "Fixed (0)" }));
    expect(onChange).toHaveBeenCalledWith("fixed");
  });
});

describe("StatCard", () => {
  it("renders label, value, suffix and hint", () => {
    render(<StatCard label="Security score" value={87} suffix="/100" hint="Good" tone="brand" />);
    expect(screen.getByText("Security score")).toBeInTheDocument();
    expect(screen.getByText("87")).toBeInTheDocument();
    expect(screen.getByText("/100")).toBeInTheDocument();
    expect(screen.getByText("Good")).toBeInTheDocument();
  });
});

describe("EmptyState", () => {
  it("always pairs the message with a next step", () => {
    render(<EmptyState title="No completed scans yet" description="Run one." action={<Link href="/dashboard/scans">Run your first scan</Link>} />);
    expect(screen.getByRole("heading", { name: "No completed scans yet" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run your first scan" })).toHaveAttribute("href", "/dashboard/scans");
  });
});
