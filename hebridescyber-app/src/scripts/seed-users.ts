// Seeds demo accounts for local testing: one admin, and four customers
// each in a different situation (no plan, Basic, Pro, Agency) so you can
// see how the dashboard's plan-aware upsell (src/components/PlanUpsell.tsx)
// and admin view (src/app/admin) actually look without manually clicking
// through Stripe Checkout five times.
//
// Uses the Supabase Admin API (auth.admin.createUser) rather than raw SQL
// against auth.users — that table's password column needs GoTrue's own
// hashing, so inserting into it directly is fragile/version-dependent.
// This is the supported way to create real, sign-in-able users from a
// script.
//
// Run with: npm run seed:users
// Requires SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY in the environment
// (same as scan-local.ts) — get these from a real Supabase project, this
// will not work against a placeholder.

import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const seedPassword = process.env.SEED_USER_PASSWORD ?? "HebridesDev123!";

if (!supabaseUrl || !serviceRoleKey) {
  console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required — see .env.example.");
  process.exit(1);
}

const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

type SeedUser = {
  email: string;
  isAdmin: boolean;
  plan: "none" | "basic" | "pro" | "agency";
  companyName: string;
};

const users: SeedUser[] = [
  { email: "admin@hebridescyber.co.uk", isAdmin: true, plan: "agency", companyName: "Hebrides Cyber (staff)" },
  { email: "no-plan-customer@example.com", isAdmin: false, plan: "none", companyName: "Lewis Crafts Co." },
  { email: "basic-customer@example.com", isAdmin: false, plan: "basic", companyName: "Stornoway Guesthouse" },
  { email: "pro-customer@example.com", isAdmin: false, plan: "pro", companyName: "Outer Hebrides SaaS Ltd" },
  { email: "agency-customer@example.com", isAdmin: false, plan: "agency", companyName: "Harris Digital Agency" },
];

async function getOrCreateAuthUser(email: string): Promise<string> {
  const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
    email,
    password: seedPassword,
    email_confirm: true, // skip the confirmation email — these are seeded, not real signups
  });

  if (!createError && created.user) return created.user.id;

  // Already exists — look it up instead. The admin API doesn't have a
  // direct getUserByEmail, so page through listUsers().
  // TODO: this is O(n) over all users — fine for a handful of seed
  // accounts, replace with a paginated search if this ever needs to scale.
  const { data: list, error: listError } = await supabaseAdmin.auth.admin.listUsers();
  if (listError) throw listError;
  const existing = list.users.find((u) => u.email === email);
  if (!existing) throw createError ?? new Error(`Could not create or find user ${email}`);
  return existing.id;
}

async function seedOne(user: SeedUser) {
  const userId = await getOrCreateAuthUser(user.email);

  await supabaseAdmin.from("users").upsert({
    id: userId,
    email: user.email,
    company_name: user.companyName,
    is_admin: user.isAdmin,
  });

  if (user.plan !== "none") {
    await supabaseAdmin.from("subscriptions").upsert(
      {
        owner: userId,
        plan: user.plan,
        status: "active",
        stripe_customer_id: `demo_${user.plan}_${userId.slice(0, 8)}`,
        updated_at: new Date().toISOString(),
      },
      { onConflict: "owner" }
    );
  }

  // A couple of demo scans per paying customer so the dashboard isn't
  // empty on first login. Inserted directly (not via run-scan) — this is
  // seed data, not a real scan, so it skips ownership verification,
  // rate limiting, and actually calling any scanner.
  if (user.plan !== "none") {
    const demoTargets = [`https://${user.companyName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.example.com`];
    if (user.plan === "agency") demoTargets.push("https://client-site-two.example.com");

    for (const targetUrl of demoTargets) {
      const { data: scan } = await supabaseAdmin
        .from("scans")
        .insert({
          owner: userId,
          target_url: targetUrl,
          status: "completed",
          proof_token: "seed-data",
          owner_verified: true,
        })
        .select("id")
        .single();

      if (scan) {
        const score = 65 + Math.floor(Math.random() * 30);
        await supabaseAdmin.from("scan_results").insert({
          scan_id: scan.id,
          score,
          summary: `Demo scan for ${targetUrl} — seeded data, not a real scan result.`,
          results: {
            target_url: targetUrl,
            checked_at: new Date().toISOString(),
            findings: [
              { severity: "high", title: "Missing security headers: content-security-policy", detail: "Seed data example finding." },
              { severity: "info", title: "Demo data", detail: "This scan was created by seed-users.ts, not a real Security Score run." },
            ],
          },
        });
      }
    }

    if (user.plan === "agency") {
      await supabaseAdmin.from("monitored_targets").upsert(
        [
          { owner: userId, target_url: "https://client-site-one.example.com" },
          { owner: userId, target_url: "https://client-site-two.example.com" },
        ],
        { onConflict: "owner,target_url" }
      );
    }
  }

  return userId;
}

async function main() {
  console.log(`Seeding ${users.length} demo users...\n`);

  for (const user of users) {
    const id = await seedOne(user);
    console.log(`✓ ${user.email} (${user.isAdmin ? "admin" : user.plan}) — id ${id}`);
  }

  console.log("\nDone. Sign in at /login with any of the emails above and this password:");
  console.log(`  ${seedPassword}`);
  console.log("\n(Set SEED_USER_PASSWORD in your env before running this script to use a different one.)");
}

main().catch((err) => {
  console.error("seed-users failed:", err);
  process.exit(1);
});
