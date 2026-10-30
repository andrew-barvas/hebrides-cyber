// The public status page, if the owner has set one up (a free UptimeRobot or
// similar hosted page). Returns null unless NEXT_PUBLIC_STATUS_PAGE_URL is a
// valid https URL, so the footer never links to a placeholder or a typo, and
// a customer is never sent to a page that doesn't exist yet.
export function statusPageUrl(raw: string | undefined = process.env.NEXT_PUBLIC_STATUS_PAGE_URL): string | null {
  const value = raw?.trim();
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname.includes(".") ? url.toString() : null;
  } catch {
    return null;
  }
}
