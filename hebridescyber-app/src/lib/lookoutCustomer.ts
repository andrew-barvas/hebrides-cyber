// Which customer an admin means in the Lookout reports tab: a user id, or the
// email they signed up with (public.users), so the analyst never has to dig a
// UUID out of the Supabase dashboard.
import type { SupabaseClient } from "@supabase/supabase-js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type CustomerRef = { id: string; email: string | null };
export type CustomerLookup = { ok: true; customer: CustomerRef } | { ok: false; status: 400 | 404 | 500; error: string };

/** Pure: is this a user id, an email, or neither? */
export function customerInputKind(input: string): "id" | "email" | null {
  const value = input.trim();
  if (UUID.test(value)) return "id";
  if (EMAIL.test(value)) return "email";
  return null;
}

export async function resolveLookoutCustomer(supabaseAdmin: SupabaseClient, input: string): Promise<CustomerLookup> {
  const value = input.trim();
  const kind = customerInputKind(value);
  if (!kind) return { ok: false, status: 400, error: "Enter the customer's email or user id." };
  // Exact, case-insensitive match: escape LIKE wildcards so "a_b@x.com" can't match "axb@x.com".
  const query = supabaseAdmin.from("users").select("id, email");
  const { data, error } = await (kind === "id" ? query.eq("id", value.toLowerCase()) : query.ilike("email", value.replace(/[\\%_]/g, (c) => `\\${c}`))).limit(2);
  if (error) return { ok: false, status: 500, error: error.message };
  const rows = (data ?? []) as Array<{ id: string; email: string | null }>;
  if (rows.length === 0) return { ok: false, status: 404, error: kind === "email" ? `No account uses ${value}.` : "No account has that user id." };
  if (rows.length > 1) return { ok: false, status: 400, error: "More than one account matches; use the user id." };
  return { ok: true, customer: { id: rows[0].id, email: rows[0].email } };
}

/** Emails for the customers in a report list, for display. A failed read just shows ids. */
export async function customerEmails(supabaseAdmin: SupabaseClient, ids: string[]): Promise<Map<string, string>> {
  const unique = [...new Set(ids)];
  if (unique.length === 0) return new Map();
  const { data, error } = await supabaseAdmin.from("users").select("id, email").in("id", unique);
  if (error) return new Map();
  return new Map(((data ?? []) as Array<{ id: string; email: string | null }>).filter((u) => u.email).map((u) => [u.id, u.email as string]));
}
