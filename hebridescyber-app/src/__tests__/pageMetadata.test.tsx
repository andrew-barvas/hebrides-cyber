import { describe, it, expect } from "vitest";
import { metadata as pricing } from "@/app/pricing/layout";
import PricingLayout from "@/app/pricing/layout";
import { metadata as contact } from "@/app/contact/layout";
import ContactLayout from "@/app/contact/layout";
import { metadata as login } from "@/app/login/layout";
import LoginLayout from "@/app/login/layout";

describe("page metadata for client-component routes", () => {
  it("gives pricing and contact their own title and description (not the home page's)", () => {
    for (const m of [pricing, contact]) {
      expect(m.title).toBeTruthy();
      // The root layout's title/description are what a route inherits without its own.
      expect(String(m.title)).not.toMatch(/^Hebrides Cyber — Security Scanning/);
      expect(m.description).toBeTruthy();
      expect(String(m.description)).not.toMatch(/CI\/CD hardening/);
      expect(String(m.description).length).toBeLessThanOrEqual(160);
    }
    expect(pricing.title).not.toBe(contact.title);
  });

  it("keeps the sign-in page out of search results", () => {
    expect(login.robots).toEqual({ index: false, follow: false });
  });

  it("layouts pass their children through", () => {
    const child = "x";
    expect(PricingLayout({ children: child })).toBe(child);
    expect(ContactLayout({ children: child })).toBe(child);
    expect(LoginLayout({ children: child })).toBe(child);
  });
});
