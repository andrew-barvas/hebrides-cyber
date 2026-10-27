import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import ClientsManager from "./ClientsManager";
import { getSession } from "@/lib/auth";

vi.mock("@/lib/auth", () => ({ getSession: vi.fn() }));

let list: { clients: unknown[]; unassigned_sites: number };
const fetchMock = vi.fn();

function respond(ok: boolean, data: unknown) {
  return Promise.resolve({ ok, json: async () => data } as Response);
}

beforeEach(() => {
  list = { clients: [{ id: "c1", name: "Acme", site_count: 2 }, { id: "c2", name: "Beta", site_count: 1 }], unassigned_sites: 3 };
  vi.mocked(getSession).mockResolvedValue({ access_token: "tok" } as never);
  fetchMock.mockReset().mockImplementation((_url: string, init: RequestInit) => (init.method === "GET" ? respond(true, list) : respond(true, {})));
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

const bodies = () => fetchMock.mock.calls.filter(([, i]) => i.method !== "GET").map(([, i]) => [i.method, JSON.parse(i.body)]);

describe("ClientsManager", () => {
  it("lists clients with site counts and the unassigned hint", async () => {
    render(<ClientsManager />);
    expect(await screen.findByText("Acme")).toBeInTheDocument();
    expect(screen.getByText(/2 sites/)).toBeInTheDocument();
    expect(screen.getByText(/1 site$/)).toBeInTheDocument();
    expect(screen.getByText(/3 sites are unassigned/)).toBeInTheDocument();
  });

  it("uses singular wording for one unassigned site", async () => {
    list.unassigned_sites = 1;
    render(<ClientsManager />);
    expect(await screen.findByText(/1 site is unassigned/)).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    list = { clients: [], unassigned_sites: 0 };
    render(<ClientsManager />);
    expect(await screen.findByText(/No clients yet/)).toBeInTheDocument();
  });

  it("creates a client, clears the field and notifies the parent", async () => {
    const onChanged = vi.fn();
    render(<ClientsManager onChanged={onChanged} />);
    await screen.findByText("Acme");
    fireEvent.change(screen.getByLabelText("Client name"), { target: { value: "Gamma" } });
    fireEvent.click(screen.getByRole("button", { name: "Add client" }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(bodies()).toEqual([["POST", { name: "Gamma" }]]);
    expect(screen.getByLabelText("Client name")).toHaveValue("");
  });

  it("renames inline, and can cancel", async () => {
    render(<ClientsManager />);
    await screen.findByText("Acme");
    fireEvent.click(screen.getAllByText("Rename")[0]);
    fireEvent.click(screen.getByText("Cancel"));
    expect(screen.queryByLabelText("Rename Acme")).not.toBeInTheDocument();
    fireEvent.click(screen.getAllByText("Rename")[0]);
    fireEvent.change(screen.getByLabelText("Rename Acme"), { target: { value: "Acme Ltd" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(bodies()).toEqual([["PATCH", { id: "c1", name: "Acme Ltd" }]]));
  });

  it("deletes after confirmation, and not when declined", async () => {
    render(<ClientsManager />);
    await screen.findByText("Acme");
    vi.mocked(window.confirm).mockReturnValueOnce(false);
    fireEvent.click(screen.getByLabelText("Delete Acme"));
    expect(bodies()).toEqual([]);
    fireEvent.click(screen.getByLabelText("Delete Acme"));
    await waitFor(() => expect(bodies()).toEqual([["DELETE", { id: "c1" }]]));
  });

  it("shows the server error and keeps the typed name on failure", async () => {
    fetchMock.mockImplementation((_u: string, init: RequestInit) =>
      init.method === "GET" ? respond(true, list) : respond(false, { error: "You already have a client with that name." }),
    );
    render(<ClientsManager />);
    await screen.findByText("Acme");
    fireEvent.change(screen.getByLabelText("Client name"), { target: { value: "Acme" } });
    fireEvent.click(screen.getByRole("button", { name: "Add client" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already have a client");
    expect(screen.getByLabelText("Client name")).toHaveValue("Acme");
  });

  it("falls back to generic errors and handles load failure and no session", async () => {
    fetchMock.mockImplementation(() => Promise.resolve({ ok: false, json: async () => { throw new Error("x"); } } as unknown as Response));
    render(<ClientsManager />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load clients");
    fireEvent.change(screen.getByLabelText("Client name"), { target: { value: "Z" } });
    fireEvent.click(screen.getByRole("button", { name: "Add client" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong"));

    vi.mocked(getSession).mockResolvedValue(null);
    fireEvent.click(screen.getByRole("button", { name: "Add client" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Not signed in."));
  });

  it("tolerates a payload without a clients list", async () => {
    fetchMock.mockImplementation(() => respond(true, {}));
    render(<ClientsManager />);
    expect(await screen.findByText(/No clients yet/)).toBeInTheDocument();
  });
});
