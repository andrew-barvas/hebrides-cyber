// Real Dockerfile base-image freshness scanning — extends the same
// repo-connection infrastructure as src/lib/scanners/dependencyManifest.ts
// (fetch a specific file from a connected repo via GitHub's contents API,
// parse it, check findings against a real data source, cap/sort for New/
// Fixed-diff determinism, never throw) to a connected repo's Dockerfile.
//
// ============================================================================
// APPROACH CHOSEN: end-of-life tag heuristic via https://endoflife.date, NOT
// OSV.dev CVE matching. Documented reasoning, per this codebase's rule that a
// finding must be evidenced (see docs/SCANNER-CONVENTIONS.md):
//
// OSV.dev's OS-ecosystem support is real, not the gap. Its schema documents
// ecosystems for Debian, Alpine, Ubuntu, Red Hat, and others (see
// https://ossf.github.io/osv-schema/#affectedpackage-field), and this was
// verified live, not assumed: querying
//   POST https://api.osv.dev/v1/query
//   {"package":{"name":"openssl","ecosystem":"Debian"},"version":"1.1.1n-0+deb11u4"}
// returns real DEBIAN-CVE-* advisories (lookupCveIds in osv.ts already
// supports passing an arbitrary ecosystem string — "Debian" works exactly
// like "npm" does).
//
// The gap is upstream of OSV.dev: querying it meaningfully needs the exact
// OS package name and exact installed version baked into the image (e.g.
// "openssl 1.1.1n-0+deb11u4"), and a Dockerfile's `FROM node:18-alpine` line
// gives us neither. It names a base image tag, not the dpkg/apk manifest that
// tag resolved to when it was built. Getting that manifest means pulling the
// actual image and inspecting its package database (what grype/trivy/syft
// do) — a materially heavier feature than reading one text file via the
// GitHub contents API, and out of scope for this module. Guessing OS package
// versions from a tag name rather than actually inspecting the image would
// be exactly the kind of fabricated finding this codebase's rule forbids.
//
// So this module checks the one thing a Dockerfile's FROM line genuinely
// proves: which named image:tag the build declares. Two evidence-based,
// low-false-positive checks follow from that alone:
//
//   1. UNPINNED TAG — `FROM node` / `FROM node:latest` (and not digest-
//      pinned) — a build-hygiene finding independent of any vulnerability
//      data. This is hadolint's own DL3006 rule ("Always tag the version of
//      an image explicitly") and Docker's own published guidance against
//      `:latest` in production builds: the same tag can silently point at a
//      different image tomorrow, so the build is not reproducible. Applies
//      to every base image, recognised family or not.
//
//   2. OUTDATED / END-OF-LIFE BASE — for the well-known image families whose
//      Docker Hub tag scheme maps cleanly onto a tracked product (node,
//      python, go, ruby, php, alpine, debian, ubuntu, postgres, mysql,
//      mongodb, redis, nginx — each verified live against
//      https://endoflife.date/api/<product>.json before being added below),
//      the declared version is checked against that product's real, sourced
//      end-of-life date. A tag whose cycle is already past its documented
//      EOL date is flagged with that date as evidence — a citable fact about
//      the exact version this Dockerfile pins, not a CVE count this module
//      cannot back.
//
// Both checks degrade to nothing rather than guessing: an unrecognised image
// family (custom registry, private image, `bitnami/node` vs official `node`),
// an unreadable/variable tag, or an endoflife.date lookup miss all mean no
// finding for that image — never a fabricated one.
//
// No Dockerfile at the repo root is a clean "not_applicable" result, not an
// error — plenty of repos aren't containerised. Never throws, matching every
// other scanner module's contract.
//
// GitHub access resolves through src/lib/githubApp.ts's resolveGithubAuth() —
// a GitHub App installation token if the customer installed the App on this
// repo, else the shared GITHUB_PAT. `owner/repo` format, plain fetch against
// api.github.com.
// ============================================================================

import type { Finding } from "./index";
import { resolveGithubAuth } from "../githubApp";
import { dockerBaseImageOutdatedRemediation, DOCKER_BASE_IMAGE_UNPINNED } from "./remediationText";
import { fetchEolProduct, isPastEol, matchEolEntry } from "./endOfLife";

// Shared with the web-technology EOL check; re-exported for existing callers.
export { isPastEol, matchEolEntry };

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;

// A Dockerfile with many build stages must not produce a finding per stage.
// Same capping rationale as dependencyManifest.ts's MAX_FINDINGS.
const MAX_IMAGES_CHECKED = 10;

function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

export type DockerBaseImageResult =
  | { status: "completed"; repo: string; imagesFound: number; findings: Finding[]; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string };

export type DockerBaseImageOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

// ---- Dockerfile fetch -------------------------------------------------------

async function fetchDockerfile(githubRepo: string, token: string): Promise<string | null> {
  // "Dockerfile" is the near-universal convention; a lowercase "dockerfile"
  // is valid on case-sensitive filesystems and does show up in the wild, so
  // it's worth the one extra round-trip before concluding "not applicable".
  for (const path of ["Dockerfile", "dockerfile"]) {
    try {
      const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/${path}`, {
        headers: ghHeaders(token),
        signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
      });
      if (!res.ok) continue;

      const body = (await res.json()) as { content?: string; encoding?: string };
      if (!body.content) continue;

      return Buffer.from(body.content, (body.encoding as BufferEncoding) ?? "base64").toString("utf-8");
    } catch {
      // Try the next candidate path.
    }
  }
  return null;
}

// ---- Dockerfile parsing -----------------------------------------------------

export type DockerfileStage = {
  /** The raw string after FROM, before ARG substitution — e.g. "node:${NODE_VERSION}". */
  imageRef: string;
  /** The `AS <name>` alias for this stage, if any. */
  alias: string | null;
};

/**
 * Extracts top-level `ARG name=default` declarations. Only ARGs with a
 * literal default are usable — an ARG with no default has no build-time
 * value we can see from the file alone, so FROM lines that reference it stay
 * unresolved (skip, not guess).
 */
export function parseTopLevelArgs(content: string): Map<string, string> {
  const args = new Map<string, string>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    const match = trimmed.match(/^ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/i);
    if (match) args.set(match[1], match[2].trim().replace(/^["']|["']$/g, ""));
  }
  return args;
}

function substituteArgs(ref: string, args: Map<string, string>): string {
  return ref.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (whole, braced, bare) => {
    const name = braced ?? bare;
    return args.get(name) ?? whole;
  });
}

/**
 * Exported for local verification: parses every `FROM` line into an ordered
 * list of build stages, with ARG defaults substituted where known. Comments
 * and non-FROM instructions are ignored. Deliberately does not attempt
 * continuation-line joining (`\` line breaks) — a FROM instruction spanning
 * multiple lines is vanishingly rare in practice.
 */
export function parseDockerfileStages(content: string): DockerfileStage[] {
  const args = parseTopLevelArgs(content);
  const stages: DockerfileStage[] = [];

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const match = trimmed.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?/i);
    if (!match) continue;

    stages.push({ imageRef: substituteArgs(match[1], args), alias: match[2] ?? null });
  }

  return stages;
}

export type ResolvedBaseImage = {
  /** The image:tag@digest string the stage ultimately resolves to, once stage-alias chains are followed. */
  imageRef: string;
  /** True if this image is what the LAST stage in the file resolves to — i.e. what actually ships. */
  isFinalStage: boolean;
};

/**
 * Multi-stage builds commonly re-use an earlier stage as a later stage's
 * base (`FROM deps AS build`) — that's a reference to a stage alias, not an
 * external image, and must be resolved through the alias chain to the real
 * external image it ultimately derives from. Judgement call, documented here
 * per the task: every DISTINCT external image referenced anywhere in the
 * file is checked (a vulnerable/EOL build-stage base is still worth knowing
 * about even if it isn't in the shipped image), but only the image the final
 * stage resolves to is marked isFinalStage — that's the one that actually
 * ships, so severity weighting downstream leans on this flag.
 */
export function resolveBaseImages(stages: DockerfileStage[]): ResolvedBaseImage[] {
  if (stages.length === 0) return [];

  const aliasMap = new Map<string, string>();
  for (const stage of stages) {
    if (stage.alias) aliasMap.set(stage.alias.toLowerCase(), stage.imageRef);
  }

  const resolve = (ref: string): string => {
    const seen = new Set<string>();
    let current = ref;
    while (aliasMap.has(current.toLowerCase()) && !seen.has(current.toLowerCase())) {
      seen.add(current.toLowerCase());
      current = aliasMap.get(current.toLowerCase())!;
    }
    return current;
  };

  const resolvedRefs = stages.map((stage) => resolve(stage.imageRef));
  const finalRef = resolvedRefs[resolvedRefs.length - 1];

  const seenExternal = new Set<string>();
  const images: ResolvedBaseImage[] = [];
  for (const ref of resolvedRefs) {
    const key = ref.toLowerCase();
    if (seenExternal.has(key)) continue;
    seenExternal.add(key);
    images.push({ imageRef: ref, isFinalStage: ref === finalRef });
  }
  return images;
}

// ---- Image reference parsing -------------------------------------------------

export type ParsedImageRef = {
  /** Everything before the tag/digest — may include a registry host and/or namespace. */
  repoPath: string;
  tag: string | null;
  digestPinned: boolean;
};

export function parseImageRef(ref: string): ParsedImageRef {
  let working = ref.trim();
  let digestPinned = false;

  const atIdx = working.indexOf("@");
  if (atIdx !== -1) {
    digestPinned = true;
    working = working.slice(0, atIdx);
  }

  // Only the last path segment can carry a ":tag" — an earlier segment's
  // colon is a registry port (e.g. "localhost:5000/node:18"), not a tag
  // separator.
  const lastSlash = working.lastIndexOf("/");
  const lastSegment = lastSlash === -1 ? working : working.slice(lastSlash + 1);
  const colonIdx = lastSegment.lastIndexOf(":");

  if (colonIdx === -1) {
    return { repoPath: working, tag: null, digestPinned };
  }
  const tag = lastSegment.slice(colonIdx + 1);
  const repoPath = lastSlash === -1 ? lastSegment.slice(0, colonIdx) : working.slice(0, lastSlash + 1) + lastSegment.slice(0, colonIdx);
  return { repoPath, tag, digestPinned };
}

/**
 * Returns the bare official-image name (e.g. "node") only when repoPath is
 * genuinely a Docker Hub official image with no registry host or
 * organisation namespace. `bitnami/node`, `ghcr.io/foo/node`, and
 * `myorg/node` are all real, different images with no reason to share
 * node's EOL schedule, so all three deliberately return null here rather
 * than being guessed at.
 */
export function officialFamilyName(repoPath: string): string | null {
  let p = repoPath.toLowerCase();
  if (p.startsWith("docker.io/")) p = p.slice("docker.io/".length);
  if (p.startsWith("library/")) p = p.slice("library/".length);
  if (p.includes("/") || p.includes(".") || p === "" || p.startsWith("$")) return null;
  return p;
}

// ---- endoflife.date lookup ---------------------------------------------------

// Verified live against https://endoflife.date/api/<value>.json before being
// added — see the module header. Keys are the bare Docker Hub official image
// name; values are the endoflife.date product slug (occasionally different,
// e.g. Docker's "node" vs endoflife.date's "nodejs").
const FAMILY_TO_PRODUCT: Record<string, string> = {
  node: "nodejs",
  nodejs: "nodejs",
  python: "python",
  golang: "go",
  go: "go",
  ruby: "ruby",
  php: "php",
  alpine: "alpine-linux",
  debian: "debian",
  ubuntu: "ubuntu",
  postgres: "postgresql",
  postgresql: "postgresql",
  mysql: "mysql",
  mongo: "mongodb",
  mongodb: "mongodb",
  redis: "redis",
  nginx: "nginx",
};

// ---- Findings ----------------------------------------------------------------

async function checkOneImage(
  image: ResolvedBaseImage,
  now: Date
): Promise<{ unpinned: Finding | null; outdated: Finding | null }> {
  const { repoPath, tag, digestPinned } = parseImageRef(image.imageRef);

  const unpinned: Finding | null =
    !digestPinned && (tag === null || tag.toLowerCase() === "latest")
      ? {
          checkId: `docker-base-image.unpinned-tag:${repoPath}`,
          severity: "low",
          title: `Base image not pinned to a specific version: ${repoPath}${tag ? `:${tag}` : ""}`,
          detail: `${image.isFinalStage ? "The final build stage" : "A build stage"} uses ${
            tag ? `the "${tag}" tag` : "no tag (implicitly \"latest\")"
          } for ${repoPath}, so the exact contents of this base image can change between builds without any change to the Dockerfile. This makes builds non-reproducible and lets an unreviewed base-image update reach production silently.`,
          remediation: DOCKER_BASE_IMAGE_UNPINNED,
        }
      : null;

  let outdated: Finding | null = null;
  const family = officialFamilyName(repoPath);
  if (family && tag && FAMILY_TO_PRODUCT[family]) {
    const product = FAMILY_TO_PRODUCT[family];
    const entries = await fetchEolProduct(product);
    if (entries) {
      const entry = matchEolEntry(entries, tag);
      if (entry && isPastEol(entry, now)) {
        const eolDate = typeof entry.eol === "string" ? entry.eol : "an unspecified date (marked end-of-life)";
        const daysOverdue =
          typeof entry.eol === "string" && !Number.isNaN(new Date(entry.eol).getTime())
            ? Math.floor((now.getTime() - new Date(entry.eol).getTime()) / (1000 * 60 * 60 * 24))
            : null;

        // More than ~2 years overdue is a materially different risk profile
        // (e.g. Node 14, Python 3.7) than a version that lapsed last month —
        // and a build-only stage that never ships is a lower risk than the
        // final stage regardless of how overdue it is.
        const longOverdue = daysOverdue !== null && daysOverdue > 730;
        const severity: Finding["severity"] = image.isFinalStage
          ? longOverdue
            ? "high"
            : "medium"
          : longOverdue
            ? "medium"
            : "low";

        outdated = {
          checkId: `docker-base-image.outdated-base:${repoPath}`,
          severity,
          title: `${image.isFinalStage ? "" : "[build stage] "}Outdated base image: ${repoPath}:${tag} (cycle ${entry.cycle} reached end-of-life ${eolDate})`,
          detail: `endoflife.date reports that ${product} ${entry.cycle} reached end-of-life on ${eolDate}${
            daysOverdue !== null ? ` — ${daysOverdue} day${daysOverdue === 1 ? "" : "s"} ago` : ""
          }. ${
            image.isFinalStage
              ? "This is the base image the final build stage resolves to, so it ships in what's deployed."
              : "This image is only used in an intermediate build stage, so it may not ship in the final image — but any tooling or libraries it installs are still built against an unmaintained base."
          } An end-of-life release no longer receives security patches from its maintainer, so any vulnerability discovered in it from this point on stays unpatched for as long as it's in use.`,
          remediation: dockerBaseImageOutdatedRemediation(repoPath, tag, entry.cycle, eolDate, product),
        };
      }
    }
  }

  return { unpinned, outdated };
}

/**
 * Exported for local verification without a GitHub token/repo: it is the
 * half of this module that must be provable against real endoflife.date
 * data alone, same rationale as dependencyManifest.ts's
 * buildDependencyFindings.
 */
export async function buildDockerBaseImageFindings(
  content: string,
  now: Date = new Date()
): Promise<{ findings: Finding[]; imagesFound: number; note?: string }> {
  const stages = parseDockerfileStages(content);
  if (stages.length === 0) {
    return { findings: [], imagesFound: 0, note: "No FROM instruction found in the Dockerfile." };
  }

  const allImages = resolveBaseImages(stages);
  const checked = allImages.slice(0, MAX_IMAGES_CHECKED);

  const results = await Promise.all(checked.map((image) => checkOneImage(image, now)));

  const findings: Finding[] = [];
  for (const r of results) {
    if (r.outdated) findings.push(r.outdated);
    if (r.unpinned) findings.push(r.unpinned);
  }

  const skipped = allImages.length - checked.length;
  const note = skipped > 0 ? `Only the first ${MAX_IMAGES_CHECKED} of ${allImages.length} distinct base images referenced were checked.` : undefined;

  return { findings, imagesFound: allImages.length, ...(note ? { note } : {}) };
}

// ---- Entry point ---------------------------------------------------------

/**
 * Scans the connected repo's root Dockerfile (if any) for unpinned or
 * end-of-life base images. Never throws.
 */
export async function scanDockerBaseImage(options: DockerBaseImageOptions): Promise<DockerBaseImageResult> {
  const githubRepo = options.githubRepo || null;

  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "no repository connected — see /account to connect one." };
  }
  if (!/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }
  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping Dockerfile base image scan. See .env.example." };
  }

  try {
    const dockerfile = await fetchDockerfile(githubRepo, token);
    if (!dockerfile) {
      return { status: "not_applicable", repo: githubRepo, findings: [], note: "No Dockerfile found at the repository root — nothing to scan." };
    }

    const { findings, imagesFound, note } = await buildDockerBaseImageFindings(dockerfile);
    return { status: "completed", repo: githubRepo, imagesFound, findings, ...(note ? { note } : {}) };
  } catch {
    // Backstop: this function's contract is that it never throws.
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "Dockerfile base image scan could not complete — treating as not applicable rather than surfacing an error finding." };
  }
}
