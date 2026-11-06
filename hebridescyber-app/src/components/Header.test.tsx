import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import Header from "./Header";

// E-30-adjacent nav declutter: this is the first test file for Header.tsx.
// Mocked before importing the component, same hoisting reason as
// MonitoredTargets.test.tsx. `state.pathname` drives next/navigation's
// usePathname() per test; `state.session`/`state.isAdmin` drive the
// supabase auth/admin lookups Header itself performs.
const { getSessionMock, onAuthStateChangeMock, fromMock, signOutMock, state } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  onAuthStateChangeMock: vi.fn(),
  fromMock: vi.fn(),
  signOutMock: vi.fn(),
  state: {
    pathname: "/",
    session: null as { user: { id: string } } | null,
    isAdmin: false,
  },
}));

const SESSION_COOKIE = "sb-test-auth-token";

vi.mock("next/navigation", () => ({
  usePathname: () => state.pathname,
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    auth: {
      onAuthStateChange: onAuthStateChangeMock,
    },
    from: fromMock,
  },
}));

vi.mock("@/lib/auth", () => ({
  signOut: signOutMock,
  getSession: getSessionMock,
}));

beforeEach(() => {
  state.pathname = "/";
  state.session = null;
  state.isAdmin = false;
  document.cookie = `${SESSION_COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  window.history.replaceState(null, "", "/");
  getSessionMock.mockReset().mockImplementation(() => Promise.resolve(state.session));
  onAuthStateChangeMock.mockReset().mockReturnValue({ data: { subscription: { unsubscribe: vi.fn() } } });
  fromMock.mockReset().mockImplementation(() => ({
    select: () => ({
      eq: () => ({
        maybeSingle: () => Promise.resolve({ data: { is_admin: state.isAdmin } }),
      }),
    }),
  }));
  signOutMock.mockReset().mockResolvedValue(undefined);
});

const MARKETING_LINKS = ["Services", "What We Check", "Pricing", "Blog", "Contact"];

async function renderSignedOut() {
  render(<Header />);
  await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());
}

async function renderSignedIn(pathname: string, isAdmin = false) {
  state.pathname = pathname;
  state.session = { user: { id: "user-1" } };
  state.isAdmin = isAdmin;
  document.cookie = `${SESSION_COOKIE}=x`;
  render(<Header />);
  await waitFor(() => expect(screen.getByText("Sign out")).toBeInTheDocument());
}

describe("Header — loading the Supabase client only when needed", () => {
  it("never asks Supabase about a signed-out visitor", async () => {
    await renderSignedOut();
    expect(getSessionMock).not.toHaveBeenCalled();
    expect(onAuthStateChangeMock).not.toHaveBeenCalled();
  });

  it("picks up a sign-in on the next navigation, without a page reload", async () => {
    const { rerender } = render(<Header />);
    await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());

    state.session = { user: { id: "user-1" } };
    document.cookie = `${SESSION_COOKIE}=x`;
    state.pathname = "/dashboard";
    rerender(<Header />);

    await waitFor(() => expect(screen.getByText("Sign out")).toBeInTheDocument());
  });

  it("loads the client on a sign-in callback URL so it can finish the sign-in", async () => {
    window.history.replaceState(null, "", "/?code=abc");
    render(<Header />);
    await waitFor(() => expect(onAuthStateChangeMock).toHaveBeenCalled());
  });

  it("returns to signed-out when the session ends", async () => {
    await renderSignedIn("/blog");
    const onChange = onAuthStateChangeMock.mock.calls[0][0];
    onChange("SIGNED_OUT", null);
    await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());
  });
});

describe("Header — marketing nav vs app-shell nav", () => {
  it("shows the full marketing nav and Sign in when signed out on the homepage", async () => {
    await renderSignedOut();
    for (const label of MARKETING_LINKS) expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText("Sign in")).toBeInTheDocument();
    expect(screen.queryByText("Dashboard")).not.toBeInTheDocument();
  });

  it("keeps the full marketing nav for a signed-in user browsing a marketing route (not session-based)", async () => {
    await renderSignedIn("/blog");
    for (const label of MARKETING_LINKS) expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getAllByText("Account").length).toBeGreaterThan(0);
    expect(screen.getByText("Sign out")).toBeInTheDocument();
  });

  it("hides the marketing nav on the app shell (/dashboard), keeping the app links", async () => {
    await renderSignedIn("/dashboard");
    for (const label of MARKETING_LINKS) expect(screen.queryByText(label)).not.toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Sign out")).toBeInTheDocument();
  });

  it("hides the marketing nav on a nested app-shell path (/account/security), not just an exact match", async () => {
    await renderSignedIn("/account/security");
    for (const label of MARKETING_LINKS) expect(screen.queryByText(label)).not.toBeInTheDocument();
  });

  it("shows the Admin link on the app shell for an admin caller", async () => {
    await renderSignedIn("/admin", true);
    expect(screen.getAllByText("Admin").length).toBeGreaterThan(0);
    for (const label of MARKETING_LINKS) expect(screen.queryByText(label)).not.toBeInTheDocument();
  });

  it("hides the marketing nav in the mobile drawer too, not just the desktop nav", async () => {
    await renderSignedIn("/dashboard");
    fireEvent.click(screen.getByLabelText("Open navigation menu"));

    const drawer = document.getElementById("mobile-nav")!;
    for (const label of MARKETING_LINKS) {
      expect(within(drawer).queryByText(label)).not.toBeInTheDocument();
    }
    expect(within(drawer).getByText("Dashboard")).toBeInTheDocument();
  });
});
