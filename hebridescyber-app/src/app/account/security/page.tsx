import { redirect } from "next/navigation";

// Two-factor setup moved into the unified account page, alongside profile,
// plan, and API keys. Kept as a redirect so existing links and bookmarks
// (and the old header nav item) still land somewhere useful.
export default function SecuritySettingsRedirect() {
  redirect("/account");
}
