// The benchmark corpus: one entry per fixture site. Expectations live beside
// it in bench/expectations/<id>.json — a target with no expectation file (or an
// expectation with no target) is a configuration error, not a silent skip.
import * as sites from "./fixtures/sites";
import type { SiteHandler } from "./fixtures/sites";

export type CorpusTarget = {
  id: string;
  description: string;
  /** A factory, so stateful fixtures (rate limiting) start fresh every run. */
  create: () => SiteHandler;
};

export const CORPUS: CorpusTarget[] = [
  { id: "hardened", description: "Well-configured static site", create: () => sites.hardened },
  { id: "spa-catch-all", description: "SPA returning its shell (echoing the path) for every URL", create: () => sites.spaCatchAll },
  { id: "spa-catch-all-nonce", description: "SPA catch-all with a per-request nonce in the shell", create: () => sites.spaCatchAllNonce },
  { id: "soft-404", description: "Unknown paths return a 200 'page not found' page", create: () => sites.soft404 },
  { id: "redirect-all", description: "Unknown paths redirect to the homepage", create: () => sites.redirectAll },
  { id: "seeded-legacy", description: "Legacy PHP/Apache box with many seeded misconfigurations", create: () => sites.seededLegacy },
  { id: "spa-with-leak", description: "SPA catch-all that also really exposes /.env and /backup.sql", create: () => sites.spaWithLeak },
  { id: "nginx-autoindex", description: "nginx directory listing on /assets/ only", create: () => sites.nginxAutoindex },
  { id: "cors-reflect", description: "Reflects any Origin with credentials allowed", create: () => sites.corsReflect },
  { id: "login-unthrottled", description: "Login form, no CSRF token, no rate limiting", create: () => sites.loginUnthrottled },
  { id: "login-throttled", description: "Login form with CSRF token and 429 throttling", create: () => sites.createLoginThrottled() },
  { id: "graphql-open", description: "GraphQL endpoint with introspection and GraphiQL exposed", create: () => sites.graphqlOpen },
  { id: "graphql-locked", description: "GraphQL endpoint with introspection off, no suggestions, no IDE", create: () => sites.graphqlLocked },
  { id: "legacy-js", description: "Outdated jQuery and jQuery UI script tags beside a current Lodash", create: () => sites.legacyJs },
  { id: "spa-login", description: "Client-rendered login that answers every POST with 200", create: () => sites.spaLogin },
];
