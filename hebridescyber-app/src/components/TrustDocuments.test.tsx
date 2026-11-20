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
