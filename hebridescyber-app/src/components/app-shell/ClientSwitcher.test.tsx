import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import ClientSwitcher from "./ClientSwitcher";

const clients = [
  { id: "c1", name: "Acme" },
  { id: "c2", name: "Beta" },
];

describe("ClientSwitcher", () => {
  it("lists All clients, each client and Unassigned, with the current value selected", () => {
    render(<ClientSwitcher clients={clients} value="c2" onChange={() => {}} />);
    const select = screen.getByLabelText(/client/i) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["All clients", "Acme", "Beta", "Unassigned"]);
    expect(select.value).toBe("c2");
  });

  it("reports the chosen scope", () => {
    const onChange = vi.fn();
    render(<ClientSwitcher clients={clients} value="all" onChange={onChange} className="mb-2" />);
    fireEvent.change(screen.getByLabelText(/client/i), { target: { value: "unassigned" } });
    expect(onChange).toHaveBeenCalledWith("unassigned");
    fireEvent.change(screen.getByLabelText(/client/i), { target: { value: "c1" } });
    expect(onChange).toHaveBeenLastCalledWith("c1");
  });
});
