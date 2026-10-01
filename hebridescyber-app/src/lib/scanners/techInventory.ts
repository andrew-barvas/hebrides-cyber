// What software a scan saw on a site, and which version — merged from
// fingerprint.ts (response headers, page HTML) and webapp.ts (CMS probes, JS
// library detection). Shared by:
//   - endOfLife.ts: is a versioned technology past its end-of-life date?
//   - emergingThreats.ts: does a newly exploited CVE cover what we saw?
// Both run against a fresh scan, and emergingThreats.ts also against results
// stored in scan_results, so this only reads plain data, never re-probes.
//
// Merge rules:
//   - webapp.ts's version wins over fingerprint.ts's where both exist:
//     Drupal's CHANGELOG and Joomla's manifest are more precise than a
//     generator tag, and CDN paths carry versions a filename lacks.
//   - A technology seen without a version is still listed, with version
//     null — "WordPress is here, version unknown" is evidence too, just
//     weaker evidence (emergingThreats.ts treats it as "possibly affected").
//   - packagedBy (a distribution named in the same header as the version)
//     only ever comes from fingerprint.ts and is dropped when webapp.ts's
//     version replaces it, since it described the other version.
import type { FingerprintResult } from "./fingerprint";
import type { WebAppResult } from "./webapp";

export type TechObservation = {
  /** fingerprint.ts / webapp.ts technology name ("PHP", "Nginx", "jQuery"…). */
  tech: string;
  version: string | null;
  /** Distribution named alongside the version ("Ubuntu"), if any. */
  packagedBy: string | null;
  /** Which module the version (or, without one, the detection) came from. */
  source: "fingerprint" | "webapp";
  /** webapp.ts already raised its own vulnerable-library finding for this. */
  reportedVulnerable: boolean;
};

const cleanVersion = (v: string | null | undefined): string | null => {
  const t = typeof v === "string" ? v.trim() : "";
  return t && t.toLowerCase() !== "unknown" ? t : null;
};

/**
 * Accepts `undefined` and malformed input as well as the typed results:
 * scans stored before a module existed deserialise without its key.
 */
export function collectTechInventory(
  fingerprint: FingerprintResult | null | undefined,
  webapp: WebAppResult | null | undefined
): TechObservation[] {
  const byTech = new Map<string, TechObservation>();

  if (fingerprint?.status === "checked" && Array.isArray(fingerprint.technologies)) {
    for (const t of fingerprint.technologies) {
      if (typeof t?.name !== "string" || !t.name) continue;
      byTech.set(t.name, {
        tech: t.name,
        version: cleanVersion(t.version),
        packagedBy: t.packagedBy ?? null,
        source: "fingerprint",
        reportedVulnerable: false,
      });
    }
  }

  const fromWebapp = (tech: string, rawVersion: string | null | undefined, reportedVulnerable = false) => {
    const version = cleanVersion(rawVersion);
    const existing = byTech.get(tech);
    if (version) {
      // Map.set on an existing key keeps its position, so output order is
      // stable: fingerprint order first, then webapp-only additions.
      byTech.set(tech, { tech, version, packagedBy: null, source: "webapp", reportedVulnerable: reportedVulnerable || Boolean(existing?.reportedVulnerable) });
    } else if (existing) {
      if (reportedVulnerable) existing.reportedVulnerable = true;
    } else {
      byTech.set(tech, { tech, version: null, packagedBy: null, source: "webapp", reportedVulnerable });
    }
  };

  if (webapp?.status === "checked") {
    if (webapp.drupal) fromWebapp("Drupal", webapp.drupal.version);
    if (webapp.joomla) fromWebapp("Joomla", webapp.joomla.version);
    for (const lib of Array.isArray(webapp.jsLibraries) ? webapp.jsLibraries : []) {
      if (typeof lib?.name !== "string" || !lib.name) continue;
      fromWebapp(lib.name, lib.version, Boolean(lib.isVulnerable));
    }
  }

  return [...byTech.values()];
}
