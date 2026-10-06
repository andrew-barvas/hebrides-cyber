import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock, verifiedState } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  verifiedState: { value: { domains: new Set<string>(["example.com"]), isAdmin: false, loaded: true } },
}));
vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));
vi.mock("@/lib/verifiedDomains", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/verifiedDomains")>()),
  useVerifiedDomains: () => verifiedState.value,
}));

import RunScanForm from "./RunScanForm";

const fetchMock = vi.fn();

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

beforeEach(() => {
  getSessionMock.mockReset().mockResolvedValue({ access_token: "tok" });
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function submit(url = "https://example.com") {
  fireEvent.change(screen.getByLabelText("Website URL"), { target: { value: url } });
  fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
}

describe("RunScanForm", () => {
  it("says a typed site isn't verified yet, and points out a verified www/apex twin", () => {
    verifiedState.value = { domains: new Set(["example.com"]), isAdmin: false, loaded: true };
    render(<RunScanForm onScanUpdate={() => {}} />);
    const input = screen.getByLabelText("Website URL");
    fireEvent.change(input, { target: { value: "https://example.com/shop" } });
    expect(screen.queryByRole("status")).toBeNull();
    fireEvent.change(input, { target: { value: "https://www.example.com" } });
    expect(screen.getByRole("status").textContent).toMatch(/www\.example\.com isn't verified.*You've verified example\.com/);
    expect(screen.getByRole("link", { name: "Verify www.example.com →" }).getAttribute("href")).toBe("/dashboard/assets#domain-verification");
    fireEvent.change(input, { target: { value: "https://other.test" } });
    expect(screen.getByRole("status").textContent).not.toMatch(/You've verified/);
  });

  it("gives no hint to admins, before the list loads, or for text that isn't a URL yet", () => {
    for (const state of [{ isAdmin: true, loaded: true }, { isAdmin: false, loaded: false }]) {
      verifiedState.value = { domains: new Set(), ...state };
      const { unmount } = render(<RunScanForm onScanUpdate={() => {}} />);
      fireEvent.change(screen.getByLabelText("Website URL"), { target: { value: "https://other.test" } });
      expect(screen.queryByRole("status")).toBeNull();
      unmount();
    }
    verifiedState.value = { domains: new Set(), isAdmin: false, loaded: true };
    render(<RunScanForm onScanUpdate={() => {}} />);
    fireEvent.change(screen.getByLabelText("Website URL"), { target: { value: "not a url" } });
    expect(screen.queryByRole("status")).toBeNull();
    verifiedState.value = { domains: new Set(["example.com"]), isAdmin: false, loaded: true };
  });

  it("labels the URL field (it was placeholder-only)", () => {
    render(<RunScanForm onScanUpdate={() => {}} />);
    expect(screen.getByLabelText("Website URL")).toHaveAttribute("type", "url");
  });

  // The most common first-scan failure — the fix is on another page now, so
  // the error has to link there rather than say "section below".
  it("links an unverified-domain failure straight to domain verification", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { scanId: "s1", proofToken: "p1" }))
      .mockResolvedValueOnce(
        jsonResponse(401, { error: "This domain hasn't been verified yet — verify it under Dashboard → Assets, then run your scan again.", code: "domain_not_verified" })
      );
    const onUpdate = vi.fn();
    render(<RunScanForm onScanUpdate={onUpdate} />);
    submit();

    expect(await screen.findByText("Verify this domain first")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to domain verification →" })).toHaveAttribute("href", "/dashboard/assets#domain-verification");
    // The scan row was created, so the list refreshes to show it (as "not
    // started") even though verification then failed.
    expect(onUpdate).toHaveBeenCalled();
  });

  it("shows a plain error, with no verification link, for other failures", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { error: "Rate limit exceeded — try again later" }));
    render(<RunScanForm onScanUpdate={() => {}} />);
    submit();

    expect(await screen.findByRole("alert")).toHaveTextContent("Rate limit exceeded");
    expect(screen.queryByRole("link", { name: /domain verification/ })).not.toBeInTheDocument();
  });

  it("surfaces the real failure reason for a scan that ran and failed", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { scanId: "s1", proofToken: "p1" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: false, status: "failed", error: "Scan failed: target unreachable: ECONNREFUSED" }));
    render(<RunScanForm onScanUpdate={() => {}} />);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("target unreachable: ECONNREFUSED");
  });

  it("reports the score, clears the field and refreshes the caller on completion", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { scanId: "s1", proofToken: "p1" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: true, status: "completed", score: 91 }));
    const onUpdate = vi.fn();
    render(<RunScanForm onScanUpdate={onUpdate} />);
    submit();

    expect(await screen.findByText("Scan complete — score 91/100.")).toBeInTheDocument();
    // Once when the row is created, once when it settles.
    await waitFor(() => expect(onUpdate).toHaveBeenCalledTimes(2));
    expect(screen.getByLabelText("Website URL")).toHaveValue("");
    // Only the first poll carries the proof token.
    expect(fetchMock.mock.calls[1][1].headers["X-Scan-Token"]).toBe("p1");
  });

  it("asks the user to sign in again rather than calling the API without a session", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<RunScanForm onScanUpdate={() => {}} />);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("Session expired");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
