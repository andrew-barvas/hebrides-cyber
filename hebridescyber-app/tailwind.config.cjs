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
        // "Cyber" accent set — used for the dark hero/header/footer chrome
        // and marketing sections (Header, Footer, homepage). Deliberately
        // NOT used as the base body theme — see globals.css comment about
        // why the app/dashboard pages stay on the light palette above.
        cyberbg: "#070B14", // near-black navy, hero/header/footer background
        cyberpanel: "#0D1524", // slightly lighter panel bg for cards on cyberbg
        cyberborder: "#1C2940", // subtle borders on dark panels
        neon: "#39FFC0", // bright accent for glow effects, links, highlights
      },
      fontFamily: {
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(57, 255, 192, 0.35)",
        glowsm: "0 0 12px rgba(57, 255, 192, 0.45)",
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
};
