# Security policy

Hebrides Cyber is a security product, so we hold our own platform to the standard
we scan others against. This file is the responsible-disclosure policy for the
**Hebrides Cyber platform itself** (this repository and the deployed service at
`hebridescyber.co.uk`) — not for vulnerabilities we report *to customers* about
*their* sites, which are delivered through the product.

## Reporting a vulnerability

Please report suspected security issues privately. Do **not** open a public issue
for anything exploitable.

- **Email:** security@hebridescyber.co.uk *(set up a monitored inbox / alias
  before publishing this file externally — see `docs/ROADMAP.md`)*
- Alternatively use GitHub's **private vulnerability reporting** on this repo
  (Security → Report a vulnerability) once the repo is enabled for it.

Include: affected URL/endpoint or file, a description, reproduction steps or PoC,
and the impact you believe it has. If you need to encrypt, say so and we will
share a key.

## Scope

In scope: the web application, its API (`/api/*`, `/api/v1/*`), authentication and
tenant-isolation (RLS), the scan pipeline's handling of secrets and SSRF, and this
repository's supply chain (CI workflows, dependencies).

Out of scope: findings about a *customer's* site (that's what the product is for);
volumetric/DoS testing; social engineering; physical attacks; and any testing that
would run active/offensive payloads against the production service without prior
written agreement.

## Our commitments

- We will acknowledge a valid report, keep you updated on remediation, and credit
  you if you wish once a fix ships.
- We will not pursue action against good-faith research that respects this scope
  and avoids privacy violations, service degradation, and data destruction.

## Known limitations (self-disclosed)

Consistent with this project's "describe reality, including what's broken" doc
rule, current platform security gaps are tracked openly in
[`docs/PRODUCT-REVIEW-2026-10.md`](hebridescyber-app/docs/PRODUCT-REVIEW-2026-10.md)
(Phase 6) and `docs/security.md`. Notable items in-flight: cloud-credential
encryption-at-rest, SSRF-guard hardening, and SHA-pinning of CI Actions.
