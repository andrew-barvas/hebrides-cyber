// Suggest monitored sites from a connected Microsoft 365 tenant
// (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 6): a light version of the
// "find what the customer forgot" that enterprise attack-surface tools do by
// mapping the internet. A tenant's verified domains are the domains the
// business actually uses for email, so one with no monitored site is a gap.
//
// Read on demand with the consent the posture check already uses
// (m365Posture.ts reads the same /domains endpoint); nothing is stored.
// Google Workspace would need a further read-only scope (Admin SDK domains),
// so it isn't offered until OT-58 is done and the scope is added.
//
// A suggestion never skips domain verification: adding it as a monitored
// site is the same as typing it in, and scanning still needs the owner to
// verify it.
import type { SupabaseClient } from "@supabase/supabase-js";
import { createGraphClient, getAppToken, m365AppConfig, type M365AppConfig } from "./m365Graph";

export type TenantDomain = { domain: string; monitored: boolean };

export type TenantDomainsResult =
  | { status: "ok"; source: "m365"; domains: TenantDomain[]; truncated: boolean }
  | { status: "not_connected" }
  | { status: "not_configured" }
  | { status: "error"; message: string };

const MAX_DOMAINS = 500;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Microsoft's own initial and routing domains, which no customer website lives on. */
function isMicrosoftDomain(domain: string): boolean {
  return /(^|\.)(onmicrosoft\.com|onmicrosoft\.de|mail\.onmicrosoft\.com|microsoftonline\.com)$/.test(domain);
}

function hostOfUrl(url: string): string | null {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
}

/** Pure. A domain counts as monitored when a monitored site is that domain or a host under it. */
export function isCoveredBy(domain: string, monitoredHosts: readonly string[]): boolean {
  return monitoredHosts.some((h) => h === domain || h.endsWith(`.${domain}`));
}

/**
 * Pure. The tenant's verified, customer-owned domains, each marked monitored
 * or not; unmonitored first, then alphabetical. Unverified, malformed and
 * Microsoft-owned domains are dropped.
 */
export function suggestTenantDomains(graphDomains: ReadonlyArray<{ id?: string; isVerified?: boolean }>, monitoredUrls: readonly string[]): TenantDomain[] {
  const hosts = monitoredUrls.map(hostOfUrl).filter((h): h is string => Boolean(h));
  const seen = new Set<string>();
  const out: TenantDomain[] = [];
  for (const d of graphDomains) {
    const domain = d.id?.trim().toLowerCase().replace(/\.$/, "");
    if (!domain || d.isVerified !== true || seen.has(domain) || !DOMAIN_RE.test(domain) || isMicrosoftDomain(domain)) continue;
    seen.add(domain);
    out.push({ domain, monitored: isCoveredBy(domain, hosts) });
  }
  return out.sort((a, b) => Number(a.monitored) - Number(b.monitored) || a.domain.localeCompare(b.domain));
}

export type TenantDomainDeps = { config?: M365AppConfig | null; fetchImpl?: typeof fetch };

/** Reads the owner's tenant domains live and compares them with their monitored sites. Never throws. */
export async function loadTenantDomains(supabaseAdmin: SupabaseClient, ownerId: string, deps: TenantDomainDeps = {}): Promise<TenantDomainsResult> {
  try {
    const config = deps.config === undefined ? m365AppConfig() : deps.config;
    if (!config) return { status: "not_configured" };

    const { data: tenant, error } = await supabaseAdmin.from("m365_tenants").select("tenant_id").eq("owner", ownerId).maybeSingle();
    if (error) return { status: "error", message: "Couldn't read your Microsoft 365 connection." };
    if (!tenant?.tenant_id) return { status: "not_connected" };

    const token = await getAppToken(tenant.tenant_id as string, config, deps.fetchImpl);
    if (!token.ok) return { status: "error", message: "Microsoft 365 didn't let us in. If your admin removed our app, reconnect it under Integrations." };

    const graph = createGraphClient(token.body.accessToken, deps.fetchImpl);
    const domains = await graph.getAll<{ id?: string; isVerified?: boolean }>("/domains?$select=id,isVerified", MAX_DOMAINS);
    if (!domains.ok) return { status: "error", message: "Microsoft 365 didn't return your domains just now. Try again later." };

    const { data: targets, error: targetsError } = await supabaseAdmin.from("monitored_targets").select("target_url").eq("owner", ownerId);
    if (targetsError) return { status: "error", message: "Couldn't read your monitored sites." };

    return {
      status: "ok",
      source: "m365",
      domains: suggestTenantDomains(domains.body.items, ((targets ?? []) as Array<{ target_url: string }>).map((t) => t.target_url)),
      truncated: domains.body.truncated,
    };
  } catch {
    return { status: "error", message: "Something went wrong reading your Microsoft 365 domains." };
  }
}
