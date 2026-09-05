import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import AccountDeletion from "./AccountDeletion";

describe("AccountDeletion", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("requires a confirm step before submitting the request", () => {
    render(<AccountDeletion token="tok" />);

    expect(screen.queryByText("Yes, request deletion")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Request account deletion"));
    expect(screen.getByText("Yes, request deletion")).toBeInTheDocument();
  });

  it("cancelling the confirm step does not call the API", () => {
    render(<AccountDeletion token="tok" />);
    fireEvent.click(screen.getByText("Request account deletion"));
    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.getByText("Request account deletion")).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("submits with the bearer token and shows the confirmation message on success", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, json: async () => ({ ok: true }) });

    render(<AccountDeletion token="tok-123" />);
    fireEvent.click(screen.getByText("Request account deletion"));
    fireEvent.click(screen.getByText("Yes, request deletion"));

    await waitFor(() => expect(screen.getByText(/Request received/)).toBeInTheDocument());

    expect(fetch).toHaveBeenCalledWith(
      "/api/account/request-deletion",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ Authorization: "Bearer tok-123" }),
      })
    );
  });

  it("shows an error and stays in the confirm state when the request fails", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: "Missing or invalid Authorization header" }),
    });

    render(<AccountDeletion token="tok" />);
    fireEvent.click(screen.getByText("Request account deletion"));
    fireEvent.click(screen.getByText("Yes, request deletion"));

    await waitFor(() => expect(screen.getByText("Missing or invalid Authorization header")).toBeInTheDocument());
    expect(screen.getByText("Yes, request deletion")).toBeInTheDocument();
  });
});
