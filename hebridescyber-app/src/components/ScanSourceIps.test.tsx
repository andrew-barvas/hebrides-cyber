import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import ScanSourceIps from "./ScanSourceIps";
import { SCANNER_EGRESS_IPS, publishedScannerIps } from "@/lib/scannerEgress";

describe("publishedScannerIps", () => {
  it("keeps literal IPv4 and IPv6 addresses", () => {
    expect(publishedScannerIps(["20.1.2.3", " 2001:db8::1 "])).toEqual(["20.1.2.3", "2001:db8::1"]);
  });

  it("drops anything that isn't an address, so a placeholder can never be published", () => {
    expect(publishedScannerIps(["TBC", "", "scanner.example.com", "20.1.2.300"])).toEqual([]);
  });

  it("publishes nothing until the owner applies the Terraform and fills the address in", () => {
    // When this starts failing because a real IP was added, delete it: that is the point.
    expect(SCANNER_EGRESS_IPS).toEqual([]);
  });
});

describe("ScanSourceIps", () => {
  it("says there is no fixed address yet, and shows none, while there is no IP", () => {
    const { container } = render(<ScanSourceIps ips={[]} />);
    expect(container.textContent).toMatch(/do not scan from a fixed address yet/);
    expect(container.querySelector("code")).toBeNull();
  });

  it("lists a published address and says it can be allowlisted", () => {
    const { container } = render(<ScanSourceIps ips={["20.1.2.3"]} />);
    expect(container.querySelector("code")?.textContent).toBe("20.1.2.3");
    expect(container.textContent).toMatch(/this fixed address/);
    expect(container.textContent).toMatch(/allowlist it/);
  });

  it("tells customers not to allowlist the fallback path's shared addresses", () => {
    const { container } = render(<ScanSourceIps ips={["20.1.2.3"]} />);
    expect(container.textContent).toMatch(/do not allowlist them/);
  });
});
