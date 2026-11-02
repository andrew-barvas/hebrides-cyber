import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import ValidationRequestButton from "./ValidationRequestButton";

const fetchMock = vi.fn();
beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

const reply = (status: number, body: unknown) => fetchMock.mockResolvedValue({ ok: status < 300, status, json: async () => body });
const open = () => render(<ValidationRequestButton scanId="scan-1" token="tok" checkId="xss.reflected" />);

describe("ValidationRequestButton", () => {
  it("sends nothing until the customer confirms, and says nothing is tested", () => {
    open();
    fireEvent.click(screen.getByRole("button", { name: "Request validation" }));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByText(/Nothing is tested until we agree the scope/)).toBeTruthy();
  });

  it("posts the scan and check with the optional note, then confirms", async () => {
    reply(201, { message: "ok" });
    open();
    fireEvent.click(screen.getByRole("button", { name: "Request validation" }));
    fireEvent.change(screen.getByLabelText(/Anything we should know/), { target: { value: "  payments  " } });
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(screen.getByText(/Request received/)).toBeTruthy());
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/findings/validation-request");
    expect(init.headers.Authorization).toBe("Bearer tok");
    expect(JSON.parse(init.body)).toEqual({ scanId: "scan-1", checkId: "xss.reflected", note: "payments" });
  });

  it("omits an empty note", async () => {
    reply(201, {});
    open();
    fireEvent.click(screen.getByRole("button", { name: "Request validation" }));
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ scanId: "scan-1", checkId: "xss.reflected" });
  });

  it("reports an already-open request and shows an error with the form kept", async () => {
    reply(409, { error: "already" });
    open();
    fireEvent.click(screen.getByRole("button", { name: "Request validation" }));
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(screen.getByText(/already open/)).toBeTruthy());
  });

  it("shows the server's message on failure and lets the customer retry", async () => {
    reply(429, { error: "Please try again later." });
    open();
    fireEvent.click(screen.getByRole("button", { name: "Request validation" }));
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(screen.getByText("Please try again later.")).toBeTruthy());
    expect(screen.getByRole("button", { name: "Send request" })).toBeTruthy();
  });
});
