// Look up a Supabase auth user by email. The auth admin API has no
// getUserByEmail, so this walks listUsers() a page at a time until it finds a
// match or runs out of users — O(n), fine for operator scripts, never for a
// request path.

import type { SupabaseClient, User } from "@supabase/supabase-js";

export const USERS_PER_PAGE = 200;

export async function findAuthUserByEmail(admin: SupabaseClient, email: string): Promise<User | undefined> {
  const wanted = email.toLowerCase();
  for (let page = 1; ; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: USERS_PER_PAGE });
    if (error) throw new Error(`Could not list users: ${error.message}`);
    const match = data.users.find((u) => u.email?.toLowerCase() === wanted);
    if (match) return match;
    if (data.users.length < USERS_PER_PAGE) return undefined;
  }
}
