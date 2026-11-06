// Lookout's plan cards: the period toggle picks the price, the button sends
// that plan and period to checkout, and a closed checkout offers a contact link.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock } = vi.hoisted(() => ({ getSessionMock: vi.fn() }));

vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));

import LookoutCheckout from "./LookoutCheckout";

describe("LookoutCheckout", () => {
  beforeEach(() => {
    getSessionMock.mockReset().mockResolvedValue({ access_token: "t" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the owner's prices for each billing period", () => {
    render(<LookoutCheckout />);
    expect(screen.getByText("£149 / month")).toBeInTheDocument();
    expect(screen.getByText("£299 / month")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Quarterly" }));
    expect(screen.getByText("£399 / quarter")).toBeInTheDocument();
    expect(screen.getByText("£799 / quarter")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Annual" }));
    expect(screen.getByText("£1,490 / year")).toBeInTheDocument();
    expect(screen.getByText("£2,990 / year")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Annual" })).toHaveAttribute("aria-pressed", "true");
  });

  it("sends the chosen plan and period to checkout, and offers a contact link while sign-up is closed", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ error: "Online sign-up for this plan isn't open yet.", code: "checkout_unavailable" }), { status: 503 })
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<LookoutCheckout />);

    fireEvent.click(screen.getByRole("button", { name: "Annual" }));
    fireEvent.click(screen.getByRole("button", { name: "Start Lookout Assured" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("isn't open yet");
    expect(screen.getByRole("link", { name: "Contact us" })).toHaveAttribute("href", "/contact");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/stripe/create-checkout-session");
    expect(JSON.parse(String(init.body))).toEqual({ plan: "lookout_assured", period: "annual" });
  });

  it("asks a signed-out visitor to sign in first", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<LookoutCheckout />);
    fireEvent.click(screen.getByRole("button", { name: "Start Lookout Essentials" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/Sign in first/));
  });

  it("keeps an Enquire link for invoiced or custom scopes", () => {
    render(<LookoutCheckout />);
    expect(screen.getByRole("link", { name: "Enquire" })).toHaveAttribute("href", "/contact");
  });
});
