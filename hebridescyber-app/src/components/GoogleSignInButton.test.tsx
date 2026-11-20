import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { googleMock } = vi.hoisted(() => ({ googleMock: vi.fn() }));
vi.mock("@/lib/auth", () => ({ signInWithGoogle: googleMock }));

import GoogleSignInButton, { googleSignInEnabled } from "./GoogleSignInButton";

describe("GoogleSignInButton", () => {
  beforeEach(() => {
    googleMock.mockReset().mockResolvedValue({ error: null });
  });

  it("is off unless NEXT_PUBLIC_GOOGLE_SIGNIN is exactly 'true'", () => {
    expect(googleSignInEnabled(undefined)).toBe(false);
    expect(googleSignInEnabled("1")).toBe(false);
    expect(googleSignInEnabled("true")).toBe(true);
    const { container } = render(<GoogleSignInButton enabled={false} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("starts Google sign-in, keeping where to land afterwards", async () => {
    render(<GoogleSignInButton enabled next="/pricing?plan=pro" />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with Google" }));
    await waitFor(() => expect(googleMock).toHaveBeenCalledWith("/pricing?plan=pro"));
  });

  it("offers the email link when Google sign-in can't start", async () => {
    googleMock.mockResolvedValue({ error: { message: "provider is not enabled" } });
    render(<GoogleSignInButton enabled />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with Google" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Try the email link instead");
  });
});
