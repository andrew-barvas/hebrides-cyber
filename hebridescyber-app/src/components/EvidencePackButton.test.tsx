import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import EvidencePackButton, { fetchEvidencePack } from "./EvidencePackButton";

const res = (status: number, body: unknown, blob = new Blob(["%PDF"])) =>
  ({ ok: status < 400, status, json: async () => body, blob: async () => blob }) as unknown as Response;

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  URL.createObjectURL = vi.fn(() => "blob:pack");
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchEvidencePack", () => {
  it("returns the PDF with the bearer token", async () => {
    fetchMock.mockResolvedValue(res(200, {}));
    expect(await fetchEvidencePack("tok")).toBeInstanceOf(Blob);
    expect(fetchMock).toHaveBeenCalledWith("/api/account/evidence-pack", { headers: { Authorization: "Bearer tok" } });
  });

  it.each([
    [403, { code: "plan_required" }, "The evidence pack is on the Pro plan and above."],
    [429, {}, "Too many requests. Try again in a few minutes."],
    [500, {}, "The evidence pack could not be generated (500)."],
  ])("explains a %i", async (status, body, message) => {
    fetchMock.mockResolvedValue(res(status, body));
    await expect(fetchEvidencePack("tok")).rejects.toThrow(message);
  });

  it("copes with an unreadable error body", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 502, json: async () => { throw new Error("not json"); } } as unknown as Response);
    await expect(fetchEvidencePack("tok")).rejects.toThrow("(502)");
  });
});

describe("EvidencePackButton", () => {
  it("is disabled without a session", () => {
    render(<EvidencePackButton token={null} />);
    expect(screen.getByRole("button", { name: "Download evidence pack" })).toBeDisabled();
  });

  it("downloads a dated PDF", async () => {
    fetchMock.mockResolvedValue(res(200, {}));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<EvidencePackButton token="tok" />);
    fireEvent.click(screen.getByRole("button", { name: "Download evidence pack" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:pack");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    click.mockRestore();
  });

  it("shows why a download failed", async () => {
    fetchMock.mockResolvedValue(res(403, { code: "plan_required" }));
    render(<EvidencePackButton token="tok" />);
    fireEvent.click(screen.getByRole("button", { name: "Download evidence pack" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Pro plan and above");
    expect(screen.getByRole("button", { name: "Download evidence pack" })).toBeEnabled();
  });
});
