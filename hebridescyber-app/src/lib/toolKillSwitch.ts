// Per-tool kill switch (admin feature flags). An admin can globally disable
// an extended-scan tool from the panel; the worker reads the
// tool_kill_switches table (migration 055) and applies the result here,
// after the scan profile has been resolved, so a disabled tool is forced
// off on EVERY scan regardless of profile or per-scan overrides — a kill
// switch, not a preference. Kept pure and unit-testable; the worker does the
// Supabase read and feeds the rows through parseDisabledTools().

import { EXTENDED_TOOL_NAMES, type ExtendedToolName } from "./scanProfiles";

const TOOL_NAME_SET = new Set<string>(EXTENDED_TOOL_NAMES);

export type KillSwitchRow = { tool_name: string; disabled: boolean };

/**
 * The set of tools an admin has switched off. Rows naming a tool this build
 * doesn't know are ignored (a renamed/removed tool must never silently
 * disable some other tool), and a row with disabled=false is not in the set.
 */
export function parseDisabledTools(rows: KillSwitchRow[] | null | undefined): Set<ExtendedToolName> {
  const disabled = new Set<ExtendedToolName>();
  for (const row of rows ?? []) {
    if (row.disabled && TOOL_NAME_SET.has(row.tool_name)) {
      disabled.add(row.tool_name as ExtendedToolName);
    }
  }
  return disabled;
}

/**
 * Returns a copy of the resolved tool-enable map with every disabled tool
 * forced to false. The kill switch only ever turns tools OFF — it never
 * enables one the profile didn't ask for — so a stale or over-broad switch
 * can't widen a scan's blast radius.
 */
export function applyKillSwitch(
  toolConfig: Record<ExtendedToolName, boolean>,
  disabled: Set<ExtendedToolName>
): Record<ExtendedToolName, boolean> {
  if (disabled.size === 0) return toolConfig;
  const result = { ...toolConfig };
  for (const name of disabled) result[name] = false;
  return result;
}
