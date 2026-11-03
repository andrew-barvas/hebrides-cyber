import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

vi.mock("@/lib/supabaseClient", () => ({
  supabase: { auth: { getSession: async () => ({ data: { session: { access_token: "tok" } } }) } },
}));

import AwsRoleConnect from "./AwsRoleConnect";

const PENDING = { id: "1", label: "prod", externalId: "hc-abc", roleArn: null };
const ARN = "arn:aws:iam::123456789012:role/HebridesCyberAudit";

function respond(roles: unknown[], platformAccountId: string | null = "111122223333") {
  return { ok: true, json: async () => ({ roles, platformAccountId }) };
}

describe("AwsRoleConnect", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("shows the external id and trust principal for a role waiting for its ARN", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(respond([PENDING]));
    render(<AwsRoleConnect />);
    expect(await screen.findAllByText(/hc-abc/)).not.toHaveLength(0);
    expect(screen.getByText("arn:aws:iam::111122223333:root")).toBeInTheDocument();
  });

  it("says the principal is unavailable when the platform account is not configured", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(respond([PENDING], null));
    render(<AwsRoleConnect />);
    expect(await screen.findByText(/not available yet/)).toBeInTheDocument();
  });

  it("shows the saved role ARN and no input once connected", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(respond([{ ...PENDING, roleArn: ARN }]));
    render(<AwsRoleConnect />);
    expect(await screen.findByText(ARN)).toBeInTheDocument();
    expect(screen.queryByText("Save role ARN")).not.toBeInTheDocument();
  });

  it("posts the label to generate an external id, then the role ARN to save it", async () => {
    const f = fetch as ReturnType<typeof vi.fn>;
    f.mockResolvedValue(respond([PENDING]));
    render(<AwsRoleConnect />);
    await screen.findAllByText(/hc-abc/);

    fireEvent.change(screen.getByLabelText("Account label"), { target: { value: "staging" } });
    fireEvent.click(screen.getByText("Generate external ID"));
    await waitFor(() => expect(f.mock.calls.some(([, init]) => init?.method === "POST" && init.body === JSON.stringify({ label: "staging" }))).toBe(true));

    fireEvent.change(screen.getByLabelText("Role ARN"), { target: { value: ARN } });
    fireEvent.click(screen.getByText("Save role ARN"));
    await waitFor(() => expect(f.mock.calls.some(([, init]) => init?.body === JSON.stringify({ label: "prod", roleArn: ARN }))).toBe(true));
    expect(f.mock.calls.find(([, init]) => init?.method === "POST")![1].headers.Authorization).toBe("Bearer tok");
  });

  it("shows the server's error when saving fails", async () => {
    const f = fetch as ReturnType<typeof vi.fn>;
    f.mockResolvedValueOnce(respond([]));
    f.mockResolvedValueOnce({ ok: false, json: async () => ({ error: "Cloud posture scanning is an Agency-plan feature." }) });
    render(<AwsRoleConnect />);
    fireEvent.change(screen.getByLabelText("Account label"), { target: { value: "x" } });
    fireEvent.click(screen.getByText("Generate external ID"));
    expect(await screen.findByText(/Agency-plan feature/)).toBeInTheDocument();
  });
});
