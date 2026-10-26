// Operator script: set a user's subscription plan directly (a manual grant,
// outside Stripe) — comps, pilots, or giving a staff account the full feature
// set. Mirrors POST /api/admin/subscription exactly: it upserts the
// subscriptions row tagged `source='admin'` with `granted_by`/`grant_reason`
// (migration 052) and writes an `admin.subscription_overridden` audit event,
// so a CLI grant is indistinguishable from one made through the admin UI. A
// later real Stripe checkout for the same owner still supersedes it.
//
// Admins are already exempt from plan gating in code (planAccess.ts returns
// "ok" for any is_admin user before reading the subscription), so for a staff
// account this is belt-and-braces / display provenance, not what unlocks
// features — but it makes the stored plan honest and visible in the admin UI.
//
// Dry run by default (prints what it would do); pass --confirm to write.
//
//   npm run account:set-plan -- <email> <plan> [reason] [--confirm]
//   e.g. npm run account:set-plan -- admin@hebridescyber.co.uk tier_a "staff full access" --confirm
//
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the environment (same
// as seed-users.ts / scan-local.ts). Will not work against a placeholder.

import { createClient } from "@supabase/supabase-js";
import { logAuditEvent } from "../lib/audit";
import { findAuthUserByEmail } from "../lib/authUsers";

const VALID_PLANS = ["basic", "pro", "agency", "tier_a"] as const;
type Plan = (typeof VALID_PLANS)[number];

const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function main() {
  if (!supabaseUrl || !serviceRoleKey) {
    fail("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required — see .env.example.");
  }

  const args = process.argv.slice(2);
  const confirm = args.includes("--confirm");
  const positional = args.filter((a) => a !== "--confirm");
  const [email, plan, reason = "manual plan grant via set-plan.ts"] = positional;

  if (!email || !plan) {
    fail("Usage: npm run account:set-plan -- <email> <plan> [reason] [--confirm]\n" + `  <plan> is one of: ${VALID_PLANS.join(", ")}`);
  }
  if (!(VALID_PLANS as readonly string[]).includes(plan)) {
    fail(`Invalid plan "${plan}". Must be one of: ${VALID_PLANS.join(", ")}`);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

  // Resolve the user by email (paged — see findAuthUserByEmail).
  const authUser = await findAuthUserByEmail(supabaseAdmin, email).catch((e: Error) => fail(e.message));
  if (!authUser) fail(`No user found with email ${email}.`);

  // Confirm a public.users profile row exists (the subscriptions.owner FK / RLS
  // and the admin UI both key off it).
  const { data: profile } = await supabaseAdmin.from("users").select("id, is_admin").eq("id", authUser.id).maybeSingle();
  if (!profile) fail(`User ${email} has no public.users profile row (auth user ${authUser.id} exists but the profile is missing).`);

  const { data: current } = await supabaseAdmin
    .from("subscriptions")
    .select("plan, status, source")
    .eq("owner", authUser.id)
    .maybeSingle();

  console.log(`User:    ${email} (${authUser.id})${(profile as { is_admin?: boolean }).is_admin ? " [admin — already exempt from plan gating]" : ""}`);
  console.log(`Current: ${current ? `${current.plan} / ${current.status} (source=${current.source ?? "?"})` : "(no subscription row)"}`);
  console.log(`New:     ${plan} / active (source=admin)`);
  console.log(`Reason:  ${reason}`);

  if (!confirm) {
    console.log("\nDry run — pass --confirm to apply.");
    return;
  }

  const { error } = await supabaseAdmin.from("subscriptions").upsert(
    {
      owner: authUser.id,
      plan: plan as Plan,
      status: "active",
      source: "admin",
      granted_by: null, // the operator CLI has no acting admin; the admin route records one. Provenance is in the audit metadata (via: set-plan.ts).
      grant_reason: reason,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "owner" }
  );
  if (error) fail(`Failed to upsert subscription: ${error.message}`);

  await logAuditEvent(supabaseAdmin, {
    actorId: null,
    action: "admin.subscription_overridden",
    resourceType: "subscription",
    resourceId: authUser.id,
    metadata: { plan, status: "active", reason, via: "set-plan.ts" },
  });

  console.log(`\n✓ ${email} is now on the ${plan} plan (active, source=admin).`);
}

main().catch((err) => fail(`set-plan failed: ${(err as Error).message}`));
