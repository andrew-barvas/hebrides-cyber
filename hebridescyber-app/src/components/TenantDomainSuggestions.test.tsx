import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { insertMock } = vi.hoisted(() => ({ insertMock: vi.fn() }));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    auth: { getUser: async () => ({ data: { user: { id: "o1" } } }) },
    from: () => ({ insert: insertMock }),
  },
}));

import TenantDomainSuggestions, { MONITORED_TARGETS_CHANGED } from "./TenantDomainSuggestions";

function respond(body: unknown) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => body }));
}

describe("TenantDomainSuggestions", () => {
  beforeEach(() => {
    insertMock.mockReset().mockResolvedValue({ error: null });
  });

  it("renders nothing when no tenant is connected or the feature isn't set up", async () => {
    respond({ status: "not_connected" });
    const { container } = render(<TenantDomainSuggestions token="t" />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("lists unmonitored tenant domains and adds one as a monitored site", async () => {
    respond({ status: "ok", source: "m365", truncated: false, domains: [{ domain: "shop-example.com", monitored: false }, { domain: "example.com", monitored: true }] });
    const changed = vi.fn();
    window.addEventListener(MONITORED_TARGETS_CHANGED, changed);
    render(<TenantDomainSuggestions token="t" />);
    expect(await screen.findByText("shop-example.com", { selector: "span.font-mono" })).toBeInTheDocument();
    expect(screen.queryByText("example.com", { selector: "span.font-mono" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Add as a monitored site for shop-example.com" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Added shop-example.com"));
    expect(insertMock).toHaveBeenCalledWith({ owner: "o1", target_url: "https://shop-example.com" });
    expect(changed).toHaveBeenCalled();
    window.removeEventListener(MONITORED_TARGETS_CHANGED, changed);
  });

  it("explains a plan-cap refusal", async () => {
    respond({ status: "ok", source: "m365", truncated: false, domains: [{ domain: "shop-example.com", monitored: false }] });
    insertMock.mockResolvedValue({ error: { code: "42501", message: "new row violates row-level security policy" } });
    render(<TenantDomainSuggestions token="t" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add as a monitored site/ }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("limit of monitored sites"));
  });

  it("says when every domain is covered, and shows a fixed error message", async () => {
    respond({ status: "ok", source: "m365", truncated: false, domains: [{ domain: "example.com", monitored: true }] });
    const { unmount } = render(<TenantDomainSuggestions token="t" />);
    expect(await screen.findByText(/Every one is already covered/)).toBeInTheDocument();
    unmount();
    respond({ status: "error", message: "Microsoft 365 didn't return your domains just now. Try again later." });
    render(<TenantDomainSuggestions token="t" />);
    expect(await screen.findByText(/didn't return your domains/)).toBeInTheDocument();
  });
});
