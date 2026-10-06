// The subscribe buttons: what a customer sees when checkout can't start,
// and when they come back from a cancelled Stripe checkout.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock, searchParams } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  searchParams: { value: new URLSearchParams() },
}));

vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));
vi.mock("next/navigation", () => ({ useSearchParams: () => searchParams.value }));

import PricingPage from "./page";

const subscribeButtons = () => screen.getAllByRole("button", { name: /subscribe|get started|choose/i });

describe("pricing page checkout", () => {
  beforeEach(() => {
    getSessionMock.mockReset().mockResolvedValue({ access_token: "t" });
    searchParams.value = new URLSearchParams();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("offers a way to get in touch when online sign-up isn't open", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "Online sign-up for this plan isn't open yet.", code: "checkout_unavailable" }), { status: 503 })));
    render(<PricingPage />);
    fireEvent.click(subscribeButtons()[0]);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("isn't open yet");
    expect(screen.getByRole("link", { name: "Contact us" }).getAttribute("href")).toBe("/contact");
  });

  it("shows other errors without the contact link", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "We couldn't start checkout." }), { status: 502 })));
    render(<PricingPage />);
    fireEvent.click(subscribeButtons()[0]);
    await screen.findByRole("alert");
    expect(screen.queryByRole("link", { name: "Contact us" })).toBeNull();
  });

  it("asks a signed-out visitor to sign in first", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<PricingPage />);
    fireEvent.click(subscribeButtons()[0]);
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/Sign in first/));
  });

  it("acknowledges a cancelled checkout, and says nothing otherwise", () => {
    const { unmount } = render(<PricingPage />);
    expect(screen.queryByText(/Checkout cancelled/)).toBeNull();
    unmount();
    searchParams.value = new URLSearchParams("checkout=cancelled");
    render(<PricingPage />);
    expect(screen.getByRole("status").textContent).toMatch(/nothing was charged/);
  });
});
