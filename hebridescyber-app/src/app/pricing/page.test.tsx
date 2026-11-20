// The subscribe buttons: what a customer sees when checkout can't start,
// and when they come back from a cancelled Stripe checkout.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock, searchParams, pushMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  searchParams: { value: new URLSearchParams() },
  pushMock: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));
vi.mock("next/navigation", () => ({ useSearchParams: () => searchParams.value, useRouter: () => ({ push: pushMock }) }));

import PricingPage from "./page";

const subscribeButtons = () => screen.getAllByRole("button", { name: /subscribe|get started|choose/i });

describe("pricing page checkout", () => {
  beforeEach(() => {
    getSessionMock.mockReset().mockResolvedValue({ access_token: "t" });
    searchParams.value = new URLSearchParams();
    pushMock.mockReset();
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

  it("takes a signed-out visitor through sign-up and back to this plan's checkout", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<PricingPage />);
    fireEvent.click(subscribeButtons()[0]);
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith(`/signup?redirect=${encodeURIComponent("/pricing?checkout=basic")}`));
  });

  it("starts the chosen plan's checkout on return from sign-up, once", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: "We couldn't start checkout." }), { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    searchParams.value = new URLSearchParams("checkout=pro");
    render(<PricingPage />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(JSON.parse(String((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body))).toEqual({ plan: "pro" });
  });

  it("ignores an unknown plan in ?checkout=", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    searchParams.value = new URLSearchParams("checkout=tier_a");
    render(<PricingPage />);
    await new Promise((r) => setTimeout(r, 20));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sells only the self-serve plans, and nothing from the unavailable offensive tier", () => {
    render(<PricingPage />);
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(
      expect.arrayContaining(["Basic", "Pro", "Agency"]),
    );
    // Tier A's tools are not_configured and the owner decided not to market them (SPRINT-PLAN H6).
    expect(screen.queryByText(/Tier A/)).toBeNull();
    expect(screen.queryByText(/offensive|exploit|credential/i)).toBeNull();
  });

  it("says what counts as a monitored site, so the plan caps hold no surprises", () => {
    render(<PricingPage />);
    const note = screen.getByText(/What counts as a monitored site\?/).closest("p");
    expect(note?.textContent).toMatch(/One web address you add/);
    expect(note?.textContent).toMatch(/without using up a site/);
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
