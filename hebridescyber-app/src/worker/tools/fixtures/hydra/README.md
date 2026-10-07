# hydra fixture

Real THC-Hydra v9.5 `-o` output-file content (Tier A offensive `credentialSpray`).

- `found-9.5.out` — a run where a password in the list authenticated the account.
  Captured by running the pinned `hydra` against a throwaway Basic-auth server
  (admin:secret) in the scratchpad (NOT committed): one success line in the
  documented format `[PORT][module] host: H   login: L   password: P`, after the
  `# Hydra v9.5 run at …` header.
- `none-9.5.out` — a run that found nothing: just the header, no result lines
  (what a run against the always-401 test-app `/api/admin` produces).

`credentialSpray.ts`'s `parseHydraOutput` is tested against both. The tool is
UNVERIFIED end-to-end (there is no real credential target in CI): only the
parser and the not_configured interlocks are tested; see the module header.
