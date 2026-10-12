import type { MetadataRoute } from "next";

// No web app manifest existed before this — "Add to Home Screen" on mobile
// fell back to a plain bookmark (browser chrome, no splash screen, generic
// icon) instead of a standalone app shell. Colors and icons match
// public/favicon.svg's navy/teal mark — icon-192.png/icon-512.png/
// apple-icon.png (public/, same mark rendered larger) and theme_color/
// background_color match globals.css's `:root.dark` block (`--c-bg: 7 11
// 20`, `--c-neon: 57 255 192`) — keep all of these in sync if the brand
// mark or its colors ever change.
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Hebrides Cyber — Security Scanning",
    short_name: "Hebrides Cyber",
    description: "Automated security scanning, penetration testing, and CI/CD hardening.",
    start_url: "/dashboard",
    display: "standalone",
    background_color: "#070B14",
    theme_color: "#070B14",
    icons: [
      { src: "/favicon.svg", sizes: "any", type: "image/svg+xml" },
      { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
  };
}
