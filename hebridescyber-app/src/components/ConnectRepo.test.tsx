import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { tables, getSessionMock } = vi.hoisted(() => ({
  tables: {} as Record<string, { data: unknown; error: unknown }>,
  getSessionMock: vi.fn(),
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: (table: string) => {
      const q: Record<string, unknown> = {
        select: () => q,
        order: () => q,
        then: (r: (v: unknown) => void) => r(tables[table] ?? { data: [], error: null }),
      };
      return q;
    },
  },
}));
vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));

import ConnectRepo from "./ConnectRepo";

const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body }) as unknown as Response;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  tables.repo_connections = {
    data: [
      { id: "r1", github_repo: "acme/site", connected_at: "2026-11-01T00:00:00Z", target_host: "www.example.com" },
      { id: "r2", github_repo: "acme/old", connected_at: "2026-10-01T00:00:00Z", target_host: null },
    ],
    error: null,
  };
  tables.monitored_targets = { data: [{ target_url: "https://www.example.com" }, { target_url: "https://shop.example.org/" }, { target_url: "not a url" }], error: null };
  getSessionMock.mockReset().mockResolvedValue({ access_token: "tok" });
  fetchMock = vi.fn(async () => json(200, { ok: true }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const bodyOf = (i = 0) => JSON.parse((fetchMock.mock.calls[i][1] as { body: string }).body);

describe("ConnectRepo", () => {
  it("lists each repository with the site it's checked on, and flags unlinked ones", async () => {
    render(<ConnectRepo />);
    expect(await screen.findByText("Checked on scans of www.example.com")).toBeInTheDocument();
    expect(screen.getByText(/Not linked to a site, so it isn.t checked/)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Site this repository belongs to" })).toHaveValue("shop.example.org");
  });

  it("connects a repository to the chosen site", async () => {
    render(<ConnectRepo />);
    await screen.findByText("Checked on scans of www.example.com");
    fireEvent.change(screen.getByPlaceholderText("owner/repo"), { target: { value: " acme/new " } });
    fireEvent.change(screen.getByRole("combobox", { name: "Site this repository belongs to" }), { target: { value: "www.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock.mock.calls[0][0]).toBe("/api/account/connect-repo");
    expect(bodyOf()).toEqual({ githubRepo: "acme/new", targetUrl: "www.example.com" });
    await waitFor(() => expect(screen.getByPlaceholderText("owner/repo")).toHaveValue(""));
  });

  it("links an older repository to a site", async () => {
    render(<ConnectRepo />);
    await screen.findByText(/Not linked to a site/);
    fireEvent.change(screen.getByRole("combobox", { name: "Site for acme/old" }), { target: { value: "www.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Link" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(bodyOf()).toEqual({ githubRepo: "acme/old", targetUrl: "www.example.com" });
  });

  it("shows the server's reason when connecting fails, and keeps what was typed", async () => {
    fetchMock.mockResolvedValue(json(400, { error: "That site isn't one of your monitored sites." }));
    render(<ConnectRepo />);
    await screen.findByText("Checked on scans of www.example.com");
    fireEvent.change(screen.getByPlaceholderText("owner/repo"), { target: { value: "acme/new" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That site isn't one of your monitored sites.");
    expect(screen.getByPlaceholderText("owner/repo")).toHaveValue("acme/new");
  });

  it("disconnects a repository", async () => {
    render(<ConnectRepo />);
    await screen.findByText("Checked on scans of www.example.com");
    fireEvent.click(screen.getAllByRole("button", { name: "Disconnect" })[0]);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect((fetchMock.mock.calls[0][1] as { method: string }).method).toBe("DELETE");
    expect(bodyOf()).toEqual({ githubRepo: "acme/site" });
  });

  it("reports a failed disconnect, and needs a session for every write", async () => {
    fetchMock.mockResolvedValue(json(500, {}));
    render(<ConnectRepo />);
    await screen.findByText("Checked on scans of www.example.com");
    fireEvent.click(screen.getAllByRole("button", { name: "Disconnect" })[0]);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not disconnect repository");

    getSessionMock.mockResolvedValue(null);
    fireEvent.click(screen.getAllByRole("button", { name: "Disconnect" })[0]);
    expect(await screen.findByText("Not signed in.")).toBeInTheDocument();
  });

  it("asks for a site first when there are none, and shows an empty list", async () => {
    tables.monitored_targets = { data: [], error: null };
    tables.repo_connections = { data: [], error: null };
    render(<ConnectRepo />);
    expect(await screen.findByText("No repository connected yet.")).toBeInTheDocument();
    expect(screen.getByText(/Add the site under Assets first/)).toBeInTheDocument();
  });
});
