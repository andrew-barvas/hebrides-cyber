import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import CookieConsent, { CookieSettingsButton, clearAnalyticsCookies, getStoredConsent, withdrawConsent } from "./CookieConsent";
import Footer from "./Footer";

const STORAGE_KEY = "hebridescyber-cookie-consent";

function cookieNames(): string[] {
  return document.cookie
    .split(";")
    .map((pair) => pair.split("=")[0].trim())
    .filter(Boolean);
}

function clearAllCookies() {
  for (const name of cookieNames()) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
}

beforeEach(() => {
  window.localStorage.clear();
  clearAllCookies();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("clearAnalyticsCookies", () => {
  it("removes the Google Analytics cookies and leaves every other cookie alone", () => {
    document.cookie = "_ga=GA1.1.111.222; path=/";
    document.cookie = "_ga_ABC123XYZ=GS2.1.s1; path=/";
    document.cookie = "_gid=GA1.1.333; path=/";
    document.cookie = "theme=dark; path=/";
    document.cookie = "sb-session=keepme; path=/";

    clearAnalyticsCookies();

    const names = cookieNames();
    expect(names).not.toContain("_ga");
    expect(names).not.toContain("_ga_ABC123XYZ");
    expect(names).not.toContain("_gid");
    // Deleting by prefix would take these too; the allow-list must not.
    expect(names).toContain("theme");
    expect(names).toContain("sb-session");
  });

  it("does not touch a cookie that merely starts with the same letters", () => {
    document.cookie = "_gaming=1; path=/";
    document.cookie = "_garden=1; path=/";

    clearAnalyticsCookies();

    expect(cookieNames()).toEqual(expect.arrayContaining(["_gaming", "_garden"]));
  });

  it("is a no-op when there are no analytics cookies", () => {
    document.cookie = "theme=dark; path=/";
    expect(() => clearAnalyticsCookies()).not.toThrow();
    expect(cookieNames()).toEqual(["theme"]);
  });
});

describe("withdrawConsent", () => {
  it("forgets the stored choice and removes the analytics cookies", () => {
    window.localStorage.setItem(STORAGE_KEY, "accepted");
    document.cookie = "_ga=GA1.1.111.222; path=/";

    withdrawConsent();

    expect(getStoredConsent()).toBeNull();
    expect(cookieNames()).not.toContain("_ga");
  });

  it("still removes the cookies when storage is blocked", () => {
    document.cookie = "_ga=GA1.1.111.222; path=/";
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
      throw new Error("storage blocked");
    });

    expect(() => withdrawConsent()).not.toThrow();
    expect(cookieNames()).not.toContain("_ga");
  });
});

describe("the withdraw round trip", () => {
  it("brings the banner back after consent was accepted and then withdrawn", () => {
    window.localStorage.setItem(STORAGE_KEY, "accepted");
    const first = render(<CookieConsent />);
    // A visitor who already chose is not asked again...
    expect(screen.queryByRole("button", { name: "Accept" })).toBeNull();
    first.unmount();

    // ...until they withdraw, after which the next page load asks again.
    withdrawConsent();
    render(<CookieConsent />);
    expect(screen.getByRole("button", { name: "Accept" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decline" })).toBeInTheDocument();
  });

  it("also lets a visitor who declined change their mind", () => {
    window.localStorage.setItem(STORAGE_KEY, "declined");
    withdrawConsent();
    expect(getStoredConsent()).toBeNull();
  });
});

describe("CookieSettingsButton", () => {
  it("withdraws consent and reloads the page when clicked", () => {
    window.localStorage.setItem(STORAGE_KEY, "accepted");
    document.cookie = "_ga=GA1.1.111.222; path=/";
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, "location", { configurable: true, value: { ...original, reload } });

    try {
      render(<CookieSettingsButton />);
      fireEvent.click(screen.getByRole("button", { name: "Cookie settings" }));

      expect(getStoredConsent()).toBeNull();
      expect(cookieNames()).not.toContain("_ga");
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: original });
    }
  });

  it("is reachable from the site footer, where the privacy policy says it is", () => {
    render(<Footer />);
    expect(screen.getByRole("button", { name: "Cookie settings" })).toBeInTheDocument();
    // It sits with the other legal links rather than somewhere a visitor would not look.
    const legal = screen.getByRole("navigation", { name: "Legal" });
    expect(legal).toContainElement(screen.getByRole("button", { name: "Cookie settings" }));
    expect(legal).toContainElement(screen.getByRole("link", { name: "Privacy Policy" }));
  });
});
