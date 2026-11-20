// Shared inventory fixtures for the device agent tests. The shapes are what
// agent/internal/collect produces from its testdata/ command output.
import type { DeviceInventory } from "./inventorySchema";

export function ubuntuInventory(overrides: Partial<DeviceInventory> = {}): DeviceInventory {
  return {
    schema_version: 1,
    agent_version: "0.1.0",
    collected_at: "2026-11-20T09:00:00Z",
    hostname: "web-01",
    os: { family: "linux", name: "Ubuntu", version: "22.04", build: "", release: "22.04.4 LTS (Jammy Jellyfish)", kernel: "5.15.0-101-generic", arch: "amd64", distro_id: "ubuntu", distro_version_id: "22.04" },
    software: [
      { name: "openssl", version: "3.0.2-0ubuntu1.10", publisher: "", source: "dpkg", installed_at: "", arch: "amd64", source_name: "openssl", source_version: "3.0.2-0ubuntu1.10" },
      { name: "libssl3", version: "3.0.2-0ubuntu1.10", publisher: "", source: "dpkg", installed_at: "", arch: "amd64", source_name: "openssl", source_version: "3.0.2-0ubuntu1.10" },
      { name: "libc6", version: "2.35-0ubuntu3.6", publisher: "", source: "dpkg", installed_at: "", arch: "amd64", source_name: "glibc", source_version: "2.35-0ubuntu3.6" },
    ],
    software_checked: true,
    pending_updates: [
      { id: "openssl", title: "openssl", version: "3.0.2-0ubuntu1.15", severity: "", security: true, released_at: "", source: "apt" },
      { id: "tzdata", title: "tzdata", version: "2024a-0ubuntu0.22.04.1", severity: "", security: false, released_at: "", source: "apt" },
    ],
    pending_updates_checked: true,
    hotfixes: [],
    truncated: false,
    errors: [],
    ...overrides,
  };
}

export function windowsInventory(overrides: Partial<DeviceInventory> = {}): DeviceInventory {
  return {
    schema_version: 1,
    agent_version: "0.1.0",
    collected_at: "2026-11-20T09:00:00Z",
    hostname: "RECEPTION-PC",
    os: { family: "windows", name: "Microsoft Windows 11 Pro", version: "10.0.22631.3447", build: "22631", release: "23H2", kernel: "", arch: "64-bit", distro_id: "", distro_version_id: "" },
    software: [
      { name: "Google Chrome", version: "123.0.6312.122", publisher: "Google LLC", source: "registry", installed_at: "2024-04-10", arch: "", source_name: "", source_version: "" },
      { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov", source: "registry", installed_at: "", arch: "", source_name: "", source_version: "" },
      { name: "Contoso Line-of-Business App", version: "4.2", publisher: "Contoso", source: "registry", installed_at: "", arch: "", source_name: "", source_version: "" },
    ],
    software_checked: true,
    pending_updates: [
      { id: "KB5036893", title: "2024-04 Cumulative Update for Windows 11 Version 23H2 (KB5036893)", version: "", severity: "critical", security: true, released_at: "2026-11-11", source: "windows-update" },
    ],
    pending_updates_checked: true,
    hotfixes: [{ id: "KB5034765", installed_on: "2026-10-14", description: "Security Update" }],
    truncated: false,
    errors: [],
    ...overrides,
  };
}
