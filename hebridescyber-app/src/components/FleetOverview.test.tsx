import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import FleetOverview from "./FleetOverview";

const { fromMock, state } = vi.hoisted(() => ({
  fromMock: vi.fn(),
  state: {
    targets: [] as Array<{ id: string; target_url: string; client_id?: string | null }>,
    scans: [] as Array<{
      id: string;
      target_url: string;
      created_at: string;
      scan_results: { score: number | null; results: { findings?: { severity: string }[] } | null }[];
    }>,
  },
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: { from: fromMock },
}));

beforeEach(() => {
  state.targets = [];
  state.scans = [];
  fromMock.mockImplementation((table: string) => {
    if (table === "monitored_targets") {
      return { select: () => ({ order: () => Promise.resolve({ data: state.targets, error: null }) }) };
    }
    if (table === "scans") {
      return {
        select: () => ({
          eq: () => ({
            order: () => ({
              limit: () => Promise.resolve({ data: state.scans, error: null }),
            }),
          }),
        }),
      };
    }
    throw new Error(`unexpected table in test: ${table}`);
  });
});

describe("FleetOverview", () => {
  it("renders nothing for zero monitored targets", () => {
    const { container } = render(<FleetOverview />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for a single monitored target (Security Overview already covers that case)", async () => {
    state.targets = [{ id: "t1", target_url: "https://example.com" }];
    const { container } = render(<FleetOverview />);

    await waitFor(() => expect(fromMock).toHaveBeenCalledWith("monitored_targets"));
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a row per target, matched to its latest scan by hostname", async () => {
    state.targets = [
      { id: "t1", target_url: "https://example.com" },
      { id: "t2", target_url: "https://other.com/" },
    ];
    state.scans = [
      {
        id: "s1",
        target_url: "https://example.com/",
        created_at: new Date().toISOString(),
        scan_results: [{ score: 92, results: { findings: [{ severity: "low" }, { severity: "info" }] } }],
      },
      {
        id: "s2",
        target_url: "https://other.com",
        created_at: new Date().toISOString(),
        scan_results: [{ score: 40, results: { findings: [{ severity: "critical" }] } }],
      },
    ];

    render(<FleetOverview />);

    expect(await screen.findByText("https://example.com")).toBeInTheDocument();
    expect(screen.getByText("https://other.com/")).toBeInTheDocument();
    expect(screen.getByText("92/100")).toBeInTheDocument();
    expect(screen.getByText("40/100")).toBeInTheDocument();
    // example.com has 1 non-info finding (the "info" one is excluded); other.com has 1.
    expect(screen.getAllByText("1")).toHaveLength(2);
  });

  it("sorts worst score first", async () => {
    state.targets = [
      { id: "t1", target_url: "https://good.com" },
      { id: "t2", target_url: "https://bad.com" },
    ];
    state.scans = [
      { id: "s1", target_url: "https://good.com", created_at: new Date().toISOString(), scan_results: [{ score: 95, results: { findings: [] } }] },
      { id: "s2", target_url: "https://bad.com", created_at: new Date().toISOString(), scan_results: [{ score: 20, results: { findings: [] } }] },
    ];

    render(<FleetOverview />);
    await screen.findByText("https://bad.com");

    const rows = screen.getAllByRole("row").slice(1); // drop header row
    expect(rows[0]).toHaveTextContent("bad.com");
    expect(rows[1]).toHaveTextContent("good.com");
  });

  it("shows 'Never scanned' and dashes for a target with no matching scan", async () => {
    state.targets = [
      { id: "t1", target_url: "https://scanned.com" },
      { id: "t2", target_url: "https://unscanned.com" },
    ];
    state.scans = [
      { id: "s1", target_url: "https://scanned.com", created_at: new Date().toISOString(), scan_results: [{ score: 70, results: { findings: [] } }] },
    ];

    render(<FleetOverview />);

    expect(await screen.findByText("Never scanned")).toBeInTheDocument();
  });
});

describe("FleetOverview — grouped by client", () => {
  const clients = [
    { id: "c1", name: "Acme" },
    { id: "c2", name: "Beta" },
  ];
  const now = new Date().toISOString();

  beforeEach(() => {
    state.targets = [
      { id: "t1", target_url: "https://a1.test", client_id: "c1" },
      { id: "t2", target_url: "https://a2.test", client_id: "c1" },
      { id: "t3", target_url: "https://b1.test", client_id: "c2" },
      { id: "t4", target_url: "https://loose.test", client_id: null },
    ] as never;
    state.scans = [
      { id: "s1", target_url: "https://a1.test", created_at: now, scan_results: [{ score: 90, results: { findings: [{ severity: "low" }] } }] },
      { id: "s2", target_url: "https://a2.test", created_at: now, scan_results: [{ score: 50, results: { findings: [{ severity: "critical" }, { severity: "critical" }] } }] },
      { id: "s3", target_url: "https://b1.test", created_at: now, scan_results: [{ score: 30, results: { findings: [] } }] },
    ];
  });

  it("renders one section per client with a roll-up score and open criticals, plus Unassigned", async () => {
    render(<FleetOverview clients={clients} />);
    expect(await screen.findByText("Acme")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
    expect(screen.getByText("Unassigned")).toBeInTheDocument();
    expect(screen.getByText("70/100")).toBeInTheDocument(); // Acme = (90+50)/2
    expect(screen.getAllByText("30/100").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("2", { selector: "span.text-danger" })).toBeInTheDocument(); // Acme's open criticals
    expect(screen.getByRole("link", { name: "Assign them to a client" })).toHaveAttribute("href", "/dashboard/assets");
    // Worst roll-up first.
    const order = Array.from(document.querySelectorAll("summary")).map((el) => el.textContent?.split(" · ")[0]);
    expect(order).toEqual(["Beta", "Acme", "Unassigned"]);
  });

  it("scopes to one client, and to Unassigned", async () => {
    const { rerender } = render(<FleetOverview clients={clients} scope="c2" />);
    expect(await screen.findByText("Beta")).toBeInTheDocument();
    expect(screen.queryByText("Acme")).not.toBeInTheDocument();
    rerender(<FleetOverview clients={clients} scope="unassigned" />);
    expect(await screen.findByText("Unassigned")).toBeInTheDocument();
    expect(screen.queryByText("Beta")).not.toBeInTheDocument();
  });

  it("shows an empty client and still renders with a single site in total", async () => {
    state.targets = [{ id: "t1", target_url: "https://a1.test", client_id: "c1" }] as never;
    state.scans = [];
    render(<FleetOverview clients={clients} />);
    expect(await screen.findByText("Acme")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
    expect(screen.getByText("No sites assigned yet.")).toBeInTheDocument();
    expect(screen.getAllByText(/Last scan never/).length).toBe(2);
  });

  it("renders nothing with no sites at all", async () => {
    state.targets = [];
    const { container } = render(<FleetOverview clients={clients} />);
    await waitFor(() => expect(fromMock).toHaveBeenCalledWith("monitored_targets"));
    expect(container).toBeEmptyDOMElement();
  });
});
