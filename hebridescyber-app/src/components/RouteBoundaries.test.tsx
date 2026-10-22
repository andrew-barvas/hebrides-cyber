import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

const captureException = vi.fn();
vi.mock("@sentry/nextjs", () => ({ captureException: (e: unknown) => captureException(e) }));

import RouteError from "./RouteError";
import RouteLoading from "./RouteLoading";

describe("RouteError", () => {
  beforeEach(() => {
    captureException.mockReset();
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  it("reports the error, names the section and offers a retry", () => {
    const reset = vi.fn();
    const error = Object.assign(new Error("boom"), { digest: "abc123" });
    render(<RouteError error={error} reset={reset} section="the dashboard" />);

    expect(captureException).toHaveBeenCalledWith(error);
    expect(screen.getByRole("alert")).toHaveTextContent("the dashboard");
    expect(screen.getByText("ref: abc123")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(reset).toHaveBeenCalledTimes(1);
  });

  it("omits the ref line when there is no digest", () => {
    render(<RouteError error={new Error("x")} reset={() => undefined} section="the admin" />);
    expect(screen.queryByText(/^ref:/)).toBeNull();
  });
});

describe("RouteLoading", () => {
  it("is an announced busy status region", () => {
    render(<RouteLoading />);
    const region = screen.getByRole("status");
    expect(region).toHaveAttribute("aria-busy", "true");
    expect(region).toHaveTextContent("Loading…");
  });
});
