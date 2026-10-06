import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock, verificationsRows } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  verificationsRows: { value: [] as { domain: string; verified_at: string | null }[] },
}));

vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));
vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: () => ({ select: () => ({ order: async () => ({ data: verificationsRows.value, error: null }) }) }),
  },
}));

import DomainVerification from "./DomainVerification";

const START = {
  domain: "example.com",
  token: "tok123",
  verified: false,
  dnsRecord: { type: "TXT", name: "example.com", value: "hebridescyber-verify=tok123" },
  file: { url: "https://example.com/.well-known/hebridescyber-verify.txt", contents: "tok123" },
};

function stubApi(...replies: { status?: number; body: unknown }[]) {
  const fetchMock = vi.fn(async () => {
    const r = replies.shift()!;
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function getInstructions() {
  fireEvent.change(screen.getByLabelText("Website to verify"), { target: { value: "https://example.com" } });
  fireEvent.click(screen.getByRole("button", { name: "Get instructions" }));
  await screen.findByText("Option A: add a DNS record");
}

describe("DomainVerification", () => {
  beforeEach(() => {
    getSessionMock.mockReset().mockResolvedValue({ access_token: "t" });
    verificationsRows.value = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lists domains already started, verified or not, so instructions survive a reload", async () => {
    verificationsRows.value = [{ domain: "done.example", verified_at: "2026-10-01T00:00:00Z" }, { domain: "pending.example", verified_at: null }];
    const fetchMock = stubApi({ body: { ...START, domain: "pending.example" } });
    render(<DomainVerification />);
    const list = await screen.findByRole("list", { name: "Your domains" });
    expect(list.textContent).toContain("done.example");
    expect(list.textContent).toContain("Verified");
    fireEvent.click(screen.getByRole("button", { name: "Show instructions" }));
    await screen.findByText("Option A: add a DNS record");
    expect(JSON.parse(String((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body))).toEqual({ action: "start", targetUrl: "https://pending.example" });
  });

  it("shows the record and file to add, each with a copy button", async () => {
    stubApi({ body: START });
    render(<DomainVerification />);
    await getInstructions();
    expect(screen.getByText("hebridescyber-verify=tok123")).toBeTruthy();
    expect(screen.getByText(START.file.url)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy value" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy url" })).toBeTruthy();
  });

  it("explains why a check failed, using the server's hints", async () => {
    stubApi({ body: START }, { body: { verified: false, hints: ["DNS: no TXT record on example.com yet.", "File: nothing at the address yet."] } });
    render(<DomainVerification />);
    await getInstructions();
    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText("DNS: no TXT record on example.com yet.")).toBeTruthy();
    expect(screen.getByText("File: nothing at the address yet.")).toBeTruthy();
  });

  it("confirms success in plain words and points to the next step", async () => {
    stubApi({ body: START }, { body: { verified: true, method: "dns" } });
    const { container } = render(<DomainVerification />);
    await getInstructions();
    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText("example.com is verified")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Run a scan/ }).getAttribute("href")).toBe("/dashboard/scans#run-a-scan");
    expect(container.textContent).not.toMatch(/dev token/i);
  });

  it("shows the server's error, such as a rate limit, and a lapsed session", async () => {
    stubApi({ status: 429, body: { error: "Too many attempts. Try again in 3 minutes." } });
    render(<DomainVerification />);
    fireEvent.change(screen.getByLabelText("Website to verify"), { target: { value: "https://example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Get instructions" }));
    expect(await screen.findByText("Too many attempts. Try again in 3 minutes.")).toBeTruthy();

    getSessionMock.mockResolvedValue(null);
    fireEvent.click(screen.getByRole("button", { name: "Get instructions" }));
    await waitFor(() => expect(screen.getByText(/session has expired/)).toBeTruthy());
  });
});
