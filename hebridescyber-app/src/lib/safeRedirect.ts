// Where to send someone after sign-in, taken from a ?redirect= or ?next=
// parameter. Only a path on this site is accepted. The auth callback builds
// `${origin}${next}`, so a value such as "@evil.example" would otherwise turn
// into https://www.hebridescyber.co.uk@evil.example, which browsers read as
// the host evil.example: an open redirect.

const MAX_LENGTH = 512;

export function safeNextPath(value: string | null | undefined, fallback = "/dashboard"): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_LENGTH) return fallback;
  // One leading slash, then not a second slash or backslash ("//host" and "/\host" are host-relative).
  if (!/^\/(?![/\\])/.test(value)) return fallback;
  // No control characters or whitespace, which browsers strip or reinterpret.
  if (/[\u0000- \u007f\\]/.test(value)) return fallback;
  return value;
}
