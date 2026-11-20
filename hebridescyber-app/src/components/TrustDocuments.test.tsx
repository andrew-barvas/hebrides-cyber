import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DocumentRequestForm } from "./DocumentRequestForm";
import { TrustDocumentsManager } from "./TrustDocumentsManager";

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("DocumentRequestForm", () => {
  it("sends the request and shows the server's neutral answer", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true, message: "Request sent. If the owner approves it, you'll get an email with a download link." }) });
    vi.stubGlobal("fetch", fetchMock);
    render(<DocumentRequestForm slug="abcdefghijkl" documentId="d1" title="CE 2026" />);
    fireEvent.click(screen.getByRole("button", { name: "Request access to CE 2026" }));
    fireEvent.change(screen.getByLabelText("Your name"), { target: { value: "Sam" } });
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "sam@insurer.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Request sent.");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/profile/abcdefghijkl/documents/d1/request");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({ name: "Sam", email: "sam@insurer.example" });
  });
});

describe("TrustDocumentsManager", () => {
  const listing = {
    documents: [{ id: "d1", title: "CE 2026", kind: "cyber_essentials", kindLabel: "Cyber Essentials certificate", visibility: "on_request", sizeBytes: 2048, uploadedAt: "2026-11-01T00:00:00Z" }],
    requests: [{ id: "r1", document_id: "d1", requester_name: "Sam", requester_email: "sam@insurer.example", requester_company: "Acme", reason: "Renewal", status: "pending", created_at: "2026-11-02T00:00:00Z", download_count: 0 }],
  };

  function mockFetch(listOk = true) {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/trust-documents?")) return { ok: listOk, status: listOk ? 200 : 403, json: async () => listing };
      if (url === "/api/trust-documents/requests/r1") return { ok: true, status: 200, json: async () => ({ status: "approved", emailed: true }) };
      if (url === "/api/trust-documents" && init?.method === "POST") return { ok: true, status: 201, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("renders nothing when the account can't use it", async () => {
    const fetchMock = mockFetch(false);
    const { container } = render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("shows waiting requests and approves one", async () => {
    const fetchMock = mockFetch();
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    expect(await screen.findByText("“Renewal”")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve request from Sam" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Approved: we've emailed them a download link.");
    const post = fetchMock.mock.calls.find(([u]) => u === "/api/trust-documents/requests/r1");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ decision: "approve" });
  });

  it("refuses a non-PDF before uploading anything", async () => {
    const fetchMock = mockFetch();
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await screen.findByText("“Renewal”");
    const input = screen.getByLabelText("PDF, up to 5 MB");
    fireEvent.change(input, { target: { files: [new File(["<html>"], "x.html", { type: "text/html" })] } });
    fireEvent.click(screen.getByRole("button", { name: "Add document" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a PDF file.");
    expect(fetchMock.mock.calls.some(([u, i]) => u === "/api/trust-documents" && i?.method === "POST")).toBe(false);
  });
});

describe("TrustDocumentsManager: the rest of the owner's actions", () => {
  const listing = {
    documents: [{ id: "d1", title: "CE 2026", kind: "cyber_essentials", kindLabel: "Cyber Essentials certificate", visibility: "on_request", sizeBytes: 2048, uploadedAt: "2026-11-01T00:00:00Z" }],
    requests: [
      { id: "r1", document_id: "d1", requester_name: "Sam", requester_email: "sam@insurer.example", requester_company: "", reason: "", status: "pending", created_at: "2026-11-02T00:00:00Z", download_count: 0 },
      { id: "r2", document_id: "d1", requester_name: "Jo", requester_email: "jo@x.example", requester_company: "", reason: "", status: "approved", created_at: "2026-11-01T00:00:00Z", download_count: 1 },
      { id: "r3", document_id: "gone", requester_name: "Al", requester_email: "al@x.example", requester_company: "", reason: "", status: "declined", created_at: "2026-10-01T00:00:00Z", download_count: 0 },
    ],
  };

  function mockAll(decide: { ok: boolean; body: unknown } = { ok: true, body: { status: "declined", emailed: true } }, upload: { ok: boolean; body: unknown } = { ok: true, body: {} }) {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/trust-documents?")) return { ok: true, status: 200, json: async () => listing };
      if (url.startsWith("/api/trust-documents/requests/")) return { ok: decide.ok, status: decide.ok ? 200 : 409, json: async () => decide.body };
      if (url === "/api/trust-documents" && init?.method === "POST") return { ok: upload.ok, status: upload.ok ? 201 : 400, json: async () => upload.body };
      return { ok: true, status: 200, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("declines, shows a decision error, and lists recent decisions", async () => {
    const fetchMock = mockAll();
    const { unmount } = render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    fireEvent.click(await screen.findByRole("button", { name: "Decline request from Sam" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Declined: we've let them know.");
    expect(fetchMock.mock.calls.some(([u, i]) => u === "/api/trust-documents/requests/r1" && JSON.parse(String(i?.body)).decision === "decline")).toBe(true);
    fireEvent.click(screen.getByText("Recent decisions"));
    expect(screen.getByText(/jo@x.example: CE 2026, approved, downloaded 1 time$/)).toBeInTheDocument();
    expect(screen.getByText(/al@x.example: a removed document, declined/)).toBeInTheDocument();
    unmount();
    mockAll({ ok: false, body: { error: "This request has already been decided." } });
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve request from Sam" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already been decided");
  });

  it("says when an approval's email didn't send", async () => {
    mockAll({ ok: true, body: { status: "approved", emailed: false } });
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve request from Sam" }));
    expect(await screen.findByRole("status")).toHaveTextContent("the email didn't send");
  });

  it("changes who can download a document, and removes one after confirming", async () => {
    const fetchMock = mockAll();
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    fireEvent.change(await screen.findByLabelText("Who can download CE 2026"), { target: { value: "public" } });
    await waitFor(() => expect(fetchMock.mock.calls.some(([u, i]) => u === "/api/trust-documents/d1" && i?.method === "PATCH")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Remove CE 2026" }));
    expect(fetchMock.mock.calls.some(([, i]) => i?.method === "DELETE")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Remove CE 2026" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([u, i]) => u === "/api/trust-documents/d1" && i?.method === "DELETE")).toBe(true));
    confirm.mockRestore();
  });

  it("uploads a PDF with the chosen kind and visibility, and shows a server refusal or an oversize file", async () => {
    const fetchMock = mockAll();
    const { unmount } = render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await screen.findByLabelText("Who can download CE 2026");
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "insurance" } });
    fireEvent.change(screen.getByLabelText(/Title/), { target: { value: "Cyber cover 2026" } });
    fireEvent.change(screen.getByLabelText("Who can download it"), { target: { value: "public" } });
    fireEvent.change(screen.getByLabelText("PDF, up to 5 MB"), { target: { files: [new File(["%PDF-1.7"], "cover.pdf", { type: "application/pdf" })] } });
    fireEvent.click(screen.getByRole("button", { name: "Add document" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Added.");
    const post = fetchMock.mock.calls.find(([u, i]) => u === "/api/trust-documents" && i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ targetUrl: "https://shop.example.com", title: "Cyber cover 2026", kind: "insurance", visibility: "public" });
    expect(JSON.parse(String(post?.[1]?.body)).dataUrl).toMatch(/^data:application\/pdf;base64,/);
    unmount();

    mockAll(undefined, { ok: false, body: { error: "That file isn't a PDF." } });
    const second = render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await screen.findByLabelText("Who can download CE 2026");
    fireEvent.change(screen.getByLabelText("PDF, up to 5 MB"), { target: { files: [new File(["%PDF-1.7"], "x.pdf", { type: "application/pdf" })] } });
    fireEvent.click(screen.getByRole("button", { name: "Add document" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That file isn't a PDF.");
    second.unmount();

    mockAll();
    render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await screen.findByLabelText("Who can download CE 2026");
    const big = new File(["x"], "big.pdf", { type: "application/pdf" });
    Object.defineProperty(big, "size", { value: 6 * 1024 * 1024 });
    fireEvent.change(screen.getByLabelText("PDF, up to 5 MB"), { target: { files: [big] } });
    fireEvent.click(screen.getByRole("button", { name: "Add document" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("over 5 MB");
  });

  it("renders nothing when the list request fails outright", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    const { container } = render(<TrustDocumentsManager targetUrl="https://shop.example.com" token="t" />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});

describe("DocumentRequestForm: optional fields and errors", () => {
  it("sends company and reason when given, and shows the server's error", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, json: async () => ({ error: "Too many requests — try again later." }) });
    vi.stubGlobal("fetch", fetchMock);
    render(<DocumentRequestForm slug="abcdefghijkl" documentId="d1" title="CE 2026" />);
    fireEvent.click(screen.getByRole("button", { name: "Request access to CE 2026" }));
    fireEvent.change(screen.getByLabelText("Your name"), { target: { value: "Sam" } });
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "sam@insurer.example" } });
    fireEvent.change(screen.getByLabelText(/Company/), { target: { value: "Acme" } });
    fireEvent.change(screen.getByLabelText(/Why you need it/), { target: { value: "Renewal" } });
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Too many requests");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({ name: "Sam", email: "sam@insurer.example", company: "Acme", reason: "Renewal" });
  });
});
