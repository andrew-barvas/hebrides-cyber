import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const { result } = vi.hoisted(() => ({ result: { data: [] as Array<{ github_repo: string }> } }));
vi.mock("@/lib/supabaseClient", () => {
  const q: Record<string, unknown> = {};
  q.select = () => q;
  q.eq = () => q;
  q.is = () => q;
  q.then = (ok: (v: unknown) => void) => Promise.resolve({ data: result.data, error: null }).then(ok);
  return { supabase: { from: () => q } };
});

import RepoLinkBanner from "./RepoLinkBanner";

beforeEach(() => {
  result.data = [];
});

describe("RepoLinkBanner", () => {
  it("names an unlinked repository and links to where it's fixed", async () => {
    result.data = [{ github_repo: "acme/site" }];
    render(<RepoLinkBanner ownerId="o1" />);
    expect(await screen.findByText("acme/site")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Choose its site" })).toHaveAttribute("href", "/dashboard/integrations#connect-repo");
  });

  it("renders nothing when every repository is linked", async () => {
    const { container } = render(<RepoLinkBanner ownerId="o1" />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
