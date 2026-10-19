// Dependency licence compliance: turns the per-package SPDX licences deps.dev
// returns (depsDev.ts) into findings. Pure — fed the inventory packages, emits
// Finding[]. Two checks:
//   - dependency-license.copyleft:<pkg> (medium) — a strong-copyleft licence
//     (GPL/AGPL/SSPL/…) on a dependency of a commercial product, which can
//     oblige the product to publish its own source;
//   - dependency-license.unknown:<pkg> (info) — a package deps.dev knows but
//     that carries no recognisable SPDX licence, so its terms are unverified.
//
// Evidence discipline: a package deps.dev couldn't be reached for, or doesn't
// cover, carries no `license` and produces NOTHING here — a failed lookup is
// never a false "unknown licence" finding. Only packages with a licence we
// read, or that deps.dev positively reports as unlicensed/non-standard, are
// considered.

import type { Finding } from "./index";
import type { DependencyInventoryPackage } from "./dependencyManifest";
import { COPYLEFT_LICENSE, UNKNOWN_LICENSE } from "./remediationText";

/** Strong/network-copyleft SPDX id prefixes that oblige source disclosure. A
 *  small, deliberately conservative default policy — matched case-insensitively
 *  against each SPDX id, prefix-wise so version suffixes (-2.0, -3.0-or-later)
 *  are covered. */
export const STRONG_COPYLEFT_PREFIXES = ["GPL-", "AGPL-", "LGPL-", "SSPL-", "OSL-", "EUPL-", "CPAL-", "RPL-"] as const;

/** deps.dev marks a licence it can't resolve to SPDX as "non-standard". */
const UNKNOWN_MARKERS = new Set(["non-standard", "noassertion", "unknown", "unlicensed"]);

/** True when any SPDX id in the list is a strong/network copyleft licence. */
export function isCopyleft(licenses: string[]): boolean {
  return licenses.some((l) => STRONG_COPYLEFT_PREFIXES.some((p) => l.toUpperCase().startsWith(p)));
}

/** True when the only "licence" present is a non-standard/unknown marker. */
export function isUnknownLicense(licenses: string[]): boolean {
  return licenses.length > 0 && licenses.every((l) => UNKNOWN_MARKERS.has(l.toLowerCase()));
}

const MAX_PER_RULE = 25;

/**
 * Licence-compliance findings from inventory packages that carry a `license`.
 * Repo-gated like the rest of dependencyManifest.ts (the inventory only exists
 * for a connected repo). One finding per package name per rule, bounded.
 */
export function buildLicenseFindings(packages: DependencyInventoryPackage[]): Finding[] {
  const copyleft = new Map<string, { version: string; licenses: string[] }>();
  const unknown = new Map<string, { version: string }>();

  for (const pkg of packages) {
    const licenses = pkg.license;
    if (!licenses || licenses.length === 0) continue; // no data → nothing to say
    if (isCopyleft(licenses)) {
      if (!copyleft.has(pkg.name)) copyleft.set(pkg.name, { version: pkg.version, licenses });
    } else if (isUnknownLicense(licenses)) {
      if (!unknown.has(pkg.name)) unknown.set(pkg.name, { version: pkg.version });
    }
  }

  const findings: Finding[] = [];
  for (const [name, { version, licenses }] of [...copyleft.entries()].slice(0, MAX_PER_RULE)) {
    findings.push({
      checkId: `dependency-license.copyleft:${name}`,
      severity: "medium",
      title: `Copyleft-licensed dependency: ${name} (${licenses.join(", ")})`,
      detail: `${name}@${version} is distributed under ${licenses.join(", ")}, a strong or network copyleft licence (per deps.dev). On a commercial or closed-source product this can oblige you to release your own source code under the same terms — AGPL/SSPL extend that obligation to software merely offered over a network. Confirm this dependency's licence is compatible with how you ship your product.`,
      remediation: COPYLEFT_LICENSE,
    });
  }
  for (const [name, { version }] of [...unknown.entries()].slice(0, MAX_PER_RULE)) {
    findings.push({
      checkId: `dependency-license.unknown:${name}`,
      severity: "info",
      title: `Dependency with an unrecognised licence: ${name}`,
      detail: `${name}@${version} carries no recognisable SPDX licence identifier (deps.dev reports it as non-standard or unlicensed). Its terms can't be verified automatically, so you can't be sure you're allowed to use it as you intend. Check the package's own LICENSE file or repository.`,
      remediation: UNKNOWN_LICENSE,
    });
  }
  return findings;
}
