// Tells the site header whether it is worth loading the Supabase client, which
// is about 67 KB of compressed JavaScript that a signed-out visitor never uses.
// Must stay free of Supabase imports, or it brings that weight straight back.
//
// A hint, not an auth check: a true result only means "load the client and ask
// it". An expired cookie costs one download and then reads as signed out.

// @supabase/ssr's default storage key, split into .0, .1... when the session
// is too big for one cookie. Written by the browser client, so never HttpOnly.
const SESSION_COOKIE = /(?:^|;\s*)sb-[^=;]*-auth-token(?:\.\d+)?=/;

// The client completes these sign-ins itself when it loads, so a landing URL
// carrying one has to load it even though no session cookie exists yet.
function isAuthCallbackUrl(search: string, hash: string): boolean {
  return new URLSearchParams(search).has("code") || /(?:^#|&)(?:access_token|error_description)=/.test(hash);
}

export function mayHaveSupabaseSession(
  cookie: string = document.cookie,
  search: string = window.location.search,
  hash: string = window.location.hash
): boolean {
  return SESSION_COOKIE.test(cookie) || isAuthCallbackUrl(search, hash);
}
