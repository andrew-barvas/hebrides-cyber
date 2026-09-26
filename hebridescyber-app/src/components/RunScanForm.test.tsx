import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock } = vi.hoisted(() => ({ getSessionMock: vi.fn() }));
vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));

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
  it("labels the URL field (it was placeholder-only)", () => {
    render(<RunScanForm onScanSettled={() => {}} />);
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
    const onSettled = vi.fn();
    render(<RunScanForm onScanSettled={onSettled} />);
    submit();

    expect(await screen.findByText("Verify this domain first")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to domain verification →" })).toHaveAttribute("href", "/dashboard/assets#domain-verification");
    expect(onSettled).not.toHaveBeenCalled();
  });

  it("shows a plain error, with no verification link, for other failures", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { error: "Rate limit exceeded — try again later" }));
    render(<RunScanForm onScanSettled={() => {}} />);
    submit();

    expect(await screen.findByRole("alert")).toHaveTextContent("Rate limit exceeded");
    expect(screen.queryByRole("link", { name: /domain verification/ })).not.toBeInTheDocument();
  });

  it("surfaces the real failure reason for a scan that ran and failed", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { scanId: "s1", proofToken: "p1" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: false, status: "failed", error: "Scan failed: target unreachable: ECONNREFUSED" }));
    render(<RunScanForm onScanSettled={() => {}} />);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("target unreachable: ECONNREFUSED");
  });

  it("reports the score, clears the field and refreshes the caller on completion", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { scanId: "s1", proofToken: "p1" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: true, status: "completed", score: 91 }));
    const onSettled = vi.fn();
    render(<RunScanForm onScanSettled={onSettled} />);
    submit();

    expect(await screen.findByText("Scan complete — score 91/100.")).toBeInTheDocument();
    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText("Website URL")).toHaveValue("");
    // Only the first poll carries the proof token.
    expect(fetchMock.mock.calls[1][1].headers["X-Scan-Token"]).toBe("p1");
  });

  it("asks the user to sign in again rather than calling the API without a session", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<RunScanForm onScanSettled={() => {}} />);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("Session expired");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
