// Next.js 16 removed the `next lint` command (see package.json's "lint"
// script, now plain `eslint .`).
//
// This previously routed eslint-config-next through @eslint/eslintrc's
// FlatCompat layer, which crashed ESLint outright with "Converting circular
// structure to JSON" — the plugin objects in the modern config self-reference
// (plugins.react closes the circle), and the legacy validator tries to
// JSON.stringify them when building an error message. The result was that
// `npm run lint` failed before reading a single source file, so nothing was
// ever actually linted.
//
// eslint-config-next 16.x already publishes native flat configs
// (Linter.Config[]) at these subpaths, so the compat layer isn't needed at
// all — import and spread them directly.
import coreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

const eslintConfig = [
  // A config object whose only key is `ignores` sets global ignores, so this
  // must stay standalone rather than being merged into a block with rules.
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "out/**",
      "coverage/**", // vitest's --coverage HTML/lcov output — generated, not source
      "playwright-report/**",
      "test-results/**",
      "next-env.d.ts",
      // Opengrep rule tests: deliberately vulnerable sample code, not app source.
      "sast-rules/**",
    ],
  },
  ...coreWebVitals,
  ...nextTypeScript,
  {
    // Must match the glob eslint-config-next registers its react / react-hooks
    // / @next/next plugins under. A bare rules object with no `files` also
    // applies to files those configs skip, where the plugins aren't in scope,
    // and ESLint then fails with "could not find plugin".
    files: ["**/*.{js,jsx,mjs,ts,tsx,mts,cts}"],
    rules: {
      // The UI's whole visual language is terminal output — "// scan
      // categories", "// access denied", "$ sudo hebrides-cyber --admin" are
      // deliberate on-screen text, not comments someone typed by mistake.
      // This rule exists to catch the mistake, and here it fires 52 times on
      // intentional design. Off rather than 52 inline disables.
      "react/jsx-no-comment-textnodes": "off",

      // Fires on the ordinary "load data once on mount" effect, which this
      // app uses in ~14 components. The rule has a real point — those do
      // cascade an extra render — but fixing it properly means moving data
      // loading to a fetching library or Suspense, which is a deliberate
      // architectural change and not something to bundle into a lint fix.
      // Warn so it stays visible instead of being silently switched off.
      "react-hooks/set-state-in-effect": "warn",

      // Blog and branding images are remote (Azure Blob) and user-supplied,
      // so next/image would need remotePatterns config and an optimizer that
      // this deployment doesn't currently run. Warn, not error.
      "@next/next/no-img-element": "warn",
    },
  },
  {
    // Exploitability Analysis Engine (docs/EXPLOITABILITY-ENGINE.md §3.6): an
    // evidence-only analysis layer that must never send network traffic or
    // call a scanner tool or validator. This is the direct-import half of that
    // guarantee; importGraph.test.ts catches the transitive case and
    // noNetwork.test.ts the runtime case. Type-only imports are allowed —
    // they are erased at compile time. Tests may import node builtins to set
    // up the traps.
    files: ["src/lib/exploitability/**/*.ts"],
    ignores: ["src/lib/exploitability/**/*.test.ts"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          paths: [
            ...["http", "https", "net", "tls", "dns", "dgram", "child_process", "http2"].flatMap((m) => [
              { name: m, message: "The exploitability engine sends no network traffic." },
              { name: `node:${m}`, message: "The exploitability engine sends no network traffic." },
            ]),
            { name: "undici", message: "The exploitability engine sends no network traffic." },
            { name: "@/lib/execTool", message: "The exploitability engine runs no tools." },
            { name: "@/lib/httpProbe", message: "The exploitability engine sends no network traffic." },
            { name: "@/lib/scanExecution", message: "The exploitability engine must not reach the scan pipeline." },
            { name: "@/lib/scanners", message: "Import Finding with `import type` — the pipeline itself is off limits.", allowTypeImports: true },
          ],
          patterns: [
            {
              group: ["@/lib/scanners/*", "!@/lib/scanners/attackMap", "!@/lib/scanners/compliance"],
              message: "Only attackMap and compliance (pure lookups) may be imported at runtime; use `import type` for anything else.",
              allowTypeImports: true,
            },
            {
              group: ["../scanners", "../scanners/*", "../../scanners", "../../scanners/*", "../execTool", "../../execTool", "../scanExecution", "../../scanExecution", "../httpProbe", "../../httpProbe"],
              message: "Use the @/ alias; relative paths would bypass the exploitability engine's import restrictions.",
            },
          ],
        },
      ],
      "no-restricted-globals": [
        "error",
        ...["fetch", "WebSocket", "XMLHttpRequest", "EventSource"].map((name) => ({
          name,
          message: "The exploitability engine sends no network traffic.",
        })),
      ],
    },
  },
  {
    // .cjs config files are CommonJS by definition — require() is correct there.
    files: ["**/*.cjs"],
    rules: { "@typescript-eslint/no-require-imports": "off" },
  },
];

export default eslintConfig;
