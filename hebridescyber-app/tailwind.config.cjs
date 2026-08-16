/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class', // dark class on <html> = cyber dark theme (see layout.tsx ThemeScript)
  content: [
    "./src/app/**/*.{ts,tsx}",
    "./src/pages/**/*.{ts,tsx}",
    "./src/components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Hebrides Cyber brand palette — see marketing/02-branding.md
        atlantic: "#0B3D5B",
        heather: "#6B4C7A",
        seafoam: "#7FD3C7",
        slatelight: "#F6F7F9",
        slatedark: "#2F3A44",
        // "Cyber" semantic set — the app chrome (header, dashboard, admin,
        // auth, scan reports) is built entirely from these five tokens.
        //
        // They resolve to CSS variables rather than fixed hex so a single
        // :root / :root.dark block in globals.css re-themes every surface at
        // once. Without this, light mode would require a `dark:` variant on
        // all ~700 token usages, and any one that got missed would render
        // white-on-white. See globals.css for the actual values.
        //
        // The `<alpha-value>` placeholder is what keeps opacity modifiers
        // (bg-cyberpanel/50, text-neon/60) working.
        cyberbg: "rgb(var(--c-bg) / <alpha-value>)", // page background
        cyberpanel: "rgb(var(--c-panel) / <alpha-value>)", // card/panel background
        cyberborder: "rgb(var(--c-border) / <alpha-value>)", // borders on panels
        cybertext: "rgb(var(--c-text) / <alpha-value>)", // primary body text
        neon: "rgb(var(--c-neon) / <alpha-value>)", // accent: links, highlights, glow
      },
      fontFamily: {
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        // Alpha is a variable too — a neon bloom reads as a glow on near-black
        // but as a smudge on white, so light mode dials it right down.
        glow: "0 0 24px rgb(var(--c-neon) / var(--c-glow, 0.35))",
        glowsm: "0 0 12px rgb(var(--c-neon) / var(--c-glow-sm, 0.45))",
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
};
