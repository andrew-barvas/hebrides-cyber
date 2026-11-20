// The agent's inventory payload, validated field by field. Everything in it
// is untrusted: a device token can be copied off a machine, so the body is
// whatever its holder chooses to send.
//
// This is the server half of the contract in agent/internal/inventory/
// inventory.go: the limits are the same numbers. Unknown keys are stripped
// (never stored), so a newer agent that sends an extra field still reports.
import { z } from "zod";

export const INVENTORY_SCHEMA_VERSION = 1;
export const LIMITS = {
  software: 5000,
  pendingUpdates: 1000,
  hotfixes: 1000,
  errors: 20,
  short: 100,
  name: 200,
  error: 300,
  /** Request body limit; also the Next.js bodyParser sizeLimit on the route. */
  bodyBytes: 2 * 1024 * 1024,
} as const;

// No control characters: they have no business in a package name and would
// end up in the dashboard and in logs.
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const text = (max: number) =>
  z
    .string()
    .max(max, `must be ${max} characters or fewer`)
    .refine((s) => !CONTROL_RE.test(s), "must not contain control characters");
const optText = (max: number) => text(max).optional().default("");
const isoDate = z
  .string()
  .max(LIMITS.short)
  .refine((s) => s === "" || /^\d{4}-\d{2}-\d{2}$/.test(s), "must be YYYY-MM-DD")
  .optional()
  .default("");

const osSchema = z.object({
  family: z.enum(["windows", "macos", "linux"]),
  name: optText(LIMITS.name),
  version: optText(LIMITS.short),
  build: optText(LIMITS.short),
  release: optText(LIMITS.name),
  kernel: optText(LIMITS.short),
  arch: optText(LIMITS.short),
  distro_id: optText(LIMITS.short),
  distro_version_id: optText(LIMITS.short),
});

const softwareSchema = z.object({
  name: text(LIMITS.name).min(1, "is required"),
  version: text(LIMITS.short),
  publisher: optText(LIMITS.name),
  source: z.enum(["registry", "dpkg", "rpm", "pkgutil", "app"]),
  installed_at: isoDate,
  arch: optText(LIMITS.short),
  source_name: optText(LIMITS.name),
  source_version: optText(LIMITS.short),
});

const pendingSchema = z.object({
  id: text(LIMITS.name).min(1, "is required"),
  title: optText(LIMITS.name),
  version: optText(LIMITS.short),
  severity: z.enum(["", "critical", "important", "moderate", "low"]).optional().default(""),
  security: z.boolean(),
  released_at: isoDate,
  source: z.enum(["apt", "dnf", "softwareupdate", "windows-update"]),
});

const hotfixSchema = z.object({
  id: text(LIMITS.short).min(1, "is required"),
  installed_on: isoDate,
  description: optText(LIMITS.name),
});

export const inventorySchema = z.object({
  schema_version: z.literal(INVENTORY_SCHEMA_VERSION),
  agent_version: text(LIMITS.short),
  collected_at: z.string().max(LIMITS.short).refine((s) => !Number.isNaN(Date.parse(s)), "must be an RFC 3339 time"),
  hostname: optText(LIMITS.name),
  os: osSchema,
  software: z.array(softwareSchema).max(LIMITS.software),
  software_checked: z.boolean(),
  pending_updates: z.array(pendingSchema).max(LIMITS.pendingUpdates),
  pending_updates_checked: z.boolean(),
  hotfixes: z.array(hotfixSchema).max(LIMITS.hotfixes).optional().default([]),
  truncated: z.boolean().optional().default(false),
  errors: z.array(text(LIMITS.error)).max(LIMITS.errors).optional().default([]),
});

export type DeviceInventory = z.infer<typeof inventorySchema>;
export type InventorySoftware = DeviceInventory["software"][number];
export type InventoryPendingUpdate = DeviceInventory["pending_updates"][number];
export type InventoryOs = DeviceInventory["os"];
