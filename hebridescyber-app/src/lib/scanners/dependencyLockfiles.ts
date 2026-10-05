// Lockfile parsers — the exact, resolved dependency tree a project installs,
// transitive dependencies included, where dependencyManifest.ts's manifest
// parsers only see the direct dependencies' declared *ranges*.
//
// Every parser here is a pure function of file contents (no I/O, no OSV
// lookups), so the same code can read a lockfile fetched from GitHub during
// a scan or two versions of one lockfile in a pull-request diff. Each
// returns one LockfilePackage per distinct name@version, with:
//   - `direct`: true when the project declares it itself, false when only
//     something else pulls it in, null when the lockfile doesn't record
//     which (yarn.lock v1 and package-lock v1 need package.json for that;
//     pass it as the optional manifest argument).
//   - `dev`: true when only development dependencies reach it, false when
//     something needed at runtime does, null/absent when unknown.
//   - `introducedVia`: the chain of ancestors (name@version) from the direct
//     dependency down to this package's parent — [] for a direct
//     dependency, absent when the lockfile records no graph.
//   - `dependsOn`: keys (name@version) of the packages it depends on, where
//     the lockfile records them.
//
// What is deliberately left out: packages not installed from the
// ecosystem's public registry (git, path/file, workspace links, private
// Cargo registries). OSV.dev matches registry name@version; a fork from git
// that happens to share a name and version would be a false match.
//
// Malformed content throws LockfileParseError, so a caller can fall back
// to the manifest rather than report an empty (and wrong) tree.

import { compareEcosystemVersions } from "./ecosystemVersion";
import { isYamlMap, parseToml, parseYamlDocuments, type TomlTable, type YamlValue } from "./lockfileSyntax";
import { normalisePyPiName } from "./osv";

export type OsvEcosystem = "npm" | "PyPI" | "Packagist" | "Go" | "Maven" | "RubyGems" | "crates.io" | "NuGet";

export type LockfilePackage = {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
  direct: boolean | null;
  dev?: boolean | null;
  /** Installed only as an optional dependency (npm/pnpm/Poetry record this). */
  optional?: boolean;
  introducedVia?: string[];
  dependsOn?: string[];
};

export type LockfileParseResult = {
  ecosystem: OsvEcosystem;
  lockfile: string;
  packages: LockfilePackage[];
  /** True when the lockfile records which package depends on which (dependsOn/introducedVia are meaningful). */
  hasGraph: boolean;
};

export class LockfileParseError extends Error {
  constructor(lockfile: string, reason: string) {
    super(`${lockfile}: ${reason}`);
    this.name = "LockfileParseError";
  }
}

export const packageKey = (name: string, version: string) => `${name}@${version}`;

/** Starts with a digit and holds only version-ish characters. Rejects "0.0.0-use.local"-style placeholders separately. */
function looksLikeVersion(v: unknown): v is string {
  return typeof v === "string" && /^\d[0-9A-Za-z.+_~-]*$/.test(v) && !/-use\.local$/.test(v);
}

// ---- Dependency graph shared by every parser -----------------------------

type RootKind = "prod" | "dev" | "unknown";
type GraphNode = { name: string; version: string; dev?: boolean | null; optional?: boolean; hidden?: boolean };

function mergeDev(a: boolean | null | undefined, b: boolean | null | undefined): boolean | null | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (a === false || b === false) return false;
  return a === true && b === true ? true : null;
}

class DepGraph {
  nodes = new Map<string, GraphNode>();
  edges = new Map<string, Set<string>>();
  roots: Map<string, RootKind> | null = null;

  constructor(private ecosystem: OsvEcosystem) {}

  /** Adds (or merges into) a node. `hidden` nodes — git gems, sibling projects — are walked through but not reported. */
  add(name: string, version: string, flags: { dev?: boolean | null; optional?: boolean; hidden?: boolean } = {}): string {
    const key = packageKey(name, version);
    const existing = this.nodes.get(key);
    if (!existing) {
      this.nodes.set(key, { name, version, ...flags });
    } else {
      existing.dev = mergeDev(existing.dev, flags.dev);
      if (flags.optional !== undefined) existing.optional = existing.optional === undefined ? flags.optional : existing.optional && flags.optional;
      if (flags.hidden === false) existing.hidden = false;
    }
    return key;
  }

  edge(from: string, to: string): void {
    if (from === to) return;
    let set = this.edges.get(from);
    if (!set) this.edges.set(from, (set = new Set()));
    set.add(to);
  }

  root(key: string, kind: RootKind): void {
    if (!this.roots) this.roots = new Map();
    const prev = this.roots.get(key);
    // prod beats unknown beats dev: a package declared both ways is needed at runtime.
    if (!prev || kind === "prod" || (kind === "unknown" && prev === "dev")) this.roots.set(key, kind);
  }

  private reach(starts: string[]): Set<string> {
    const seen = new Set<string>(starts);
    const queue = [...starts];
    while (queue.length) {
      for (const child of this.edges.get(queue.shift()!) ?? []) {
        if (!seen.has(child) && this.nodes.has(child)) {
          seen.add(child);
          queue.push(child);
        }
      }
    }
    return seen;
  }

  finalize(): LockfilePackage[] {
    const sortedKeys = [...this.nodes.keys()].sort();
    const roots = this.roots;
    const parent = new Map<string, string | null>();
    let reachProd = new Set<string>();
    let reachDev = new Set<string>();
    let reachUnknown = new Set<string>();

    if (roots) {
      const byKind = (k: RootKind) => [...roots].filter(([key, kind]) => kind === k && this.nodes.has(key)).map(([key]) => key).sort();
      reachProd = this.reach(byKind("prod"));
      reachUnknown = this.reach(byKind("unknown"));
      reachDev = this.reach(byKind("dev"));

      // Shortest path from the runtime roots first, then unknown, then dev:
      // "introduced via" names the production route whenever there is one,
      // even if a dev-only route is shorter.
      for (const kind of ["prod", "unknown", "dev"] as const) {
        const queue: string[] = [];
        for (const key of byKind(kind)) {
          if (!parent.has(key)) {
            parent.set(key, null);
            queue.push(key);
          } else if (parent.get(key) !== null) {
            parent.set(key, null); // a root is its own route in
          }
        }
        while (queue.length) {
          const key = queue.shift()!;
          for (const child of [...(this.edges.get(key) ?? [])].sort()) {
            if (!parent.has(child) && this.nodes.has(child)) {
              parent.set(child, key);
              queue.push(child);
            }
          }
        }
      }
    }

    const out: LockfilePackage[] = [];
    for (const key of sortedKeys) {
      const node = this.nodes.get(key)!;
      if (node.hidden) continue;

      let dev = node.dev;
      if (dev === undefined && roots) {
        dev = reachProd.has(key) ? false : reachUnknown.has(key) ? null : reachDev.has(key) ? true : null;
      }

      let introducedVia: string[] | undefined;
      if (roots && parent.has(key)) {
        introducedVia = [];
        for (let p = parent.get(key); p; p = parent.get(p)) {
          const pn = this.nodes.get(p)!;
          introducedVia.unshift(packageKey(pn.name, pn.version));
        }
      }

      const children = [...(this.edges.get(key) ?? [])].filter((c) => this.nodes.has(c) && !this.nodes.get(c)!.hidden).sort();
      out.push({
        ecosystem: this.ecosystem,
        name: node.name,
        version: node.version,
        direct: roots ? roots.has(key) : null,
        ...(dev !== undefined ? { dev } : {}),
        ...(node.optional ? { optional: true } : {}),
        ...(introducedVia ? { introducedVia } : {}),
        ...(children.length ? { dependsOn: children } : {}),
      });
    }
    return out;
  }
}

function parseJson(raw: string, lockfile: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(raw.replace(/^﻿/, ""));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new LockfileParseError(lockfile, `not valid JSON (${(err as Error).message})`);
  }
}

const asRecord = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const asStringRecord = (v: unknown): Record<string, string> =>
  Object.fromEntries(Object.entries(asRecord(v)).filter((e): e is [string, string] => typeof e[1] === "string"));

/** A package.json's declared dependency names, split runtime vs development. */
export type NpmManifestDeps = { prod: Record<string, string>; dev: Record<string, string> };

export function readPackageJsonDeps(raw: string | null | undefined): NpmManifestDeps | null {
  if (!raw) return null;
  try {
    const pkg = asRecord(JSON.parse(raw));
    return {
      prod: { ...asStringRecord(pkg.peerDependencies), ...asStringRecord(pkg.optionalDependencies), ...asStringRecord(pkg.dependencies) },
      dev: asStringRecord(pkg.devDependencies),
    };
  } catch {
    return null;
  }
}

// ---- npm: package-lock.json / npm-shrinkwrap.json (v1, v2, v3) -----------

// A dependency installed from git, a local path or a link is not the
// registry package OSV.dev knows under that name.
const NPM_NON_REGISTRY_RE = /^(git[+:]|github:|gitlab:|bitbucket:|file:|link:|workspace:)/i;

type NpmLockEntry = {
  name?: string;
  version?: string;
  resolved?: string;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  link?: boolean;
  dependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  requires?: Record<string, unknown> | boolean;
};

/** Node's resolution: the nearest node_modules/<name> walking up from `fromPath`. */
function resolveNodeModule(paths: Set<string>, fromPath: string, name: string): string | null {
  let base = fromPath;
  for (;;) {
    const candidate = `${base ? `${base}/` : ""}node_modules/${name}`;
    if (paths.has(candidate)) return candidate;
    if (!base) return null;
    const idx = base.lastIndexOf("node_modules/");
    base = idx <= 0 ? "" : base.slice(0, idx - 1);
  }
}

function npmNameFromPath(path: string): string {
  return path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
}

/**
 * package-lock.json / npm-shrinkwrap.json. v2 and v3 carry a `packages` map
 * keyed by install path, with the root project's own declarations under ""
 * and authoritative dev/optional flags; v1 only has the nested
 * `dependencies` tree, so which packages are direct comes from
 * `packageJson` when it's given (else `direct` is null).
 */
export function parseNpmPackageLock(raw: string, packageJson?: string | null, lockfile = "package-lock.json"): LockfileParseResult {
  const lock = parseJson(raw, lockfile);
  const graph = new DepGraph("npm");
  const entries = new Map<string, NpmLockEntry>();

  if (lock.packages && typeof lock.packages === "object") {
    for (const [path, e] of Object.entries(asRecord(lock.packages))) entries.set(path, asRecord(e) as NpmLockEntry);
  } else if (lock.dependencies && typeof lock.dependencies === "object") {
    // v1: rebuild install paths from the nesting.
    const walk = (deps: Record<string, unknown>, prefix: string) => {
      for (const [name, value] of Object.entries(deps)) {
        const e = asRecord(value) as NpmLockEntry;
        const path = `${prefix}node_modules/${name}`;
        let version = e.version;
        let realName: string | undefined;
        const alias = typeof version === "string" ? /^npm:((?:@[^/]+\/)?[^@]+)@(.+)$/.exec(version) : null;
        if (alias) {
          realName = alias[1];
          version = alias[2];
        }
        entries.set(path, {
          ...e,
          name: realName,
          version,
          dependencies: typeof e.requires === "object" ? (e.requires as Record<string, unknown>) : {},
        });
        if (e.dependencies) walk(asRecord(e.dependencies), `${path}/`);
      }
    };
    walk(asRecord(lock.dependencies), "");
  } else {
    throw new LockfileParseError(lockfile, "no `packages` or `dependencies` section");
  }

  const allPaths = new Set(entries.keys());
  const pathToKey = new Map<string, string>();
  for (const [path, e] of entries) {
    if (!path.includes("node_modules/") || e.link) continue;
    if (!looksLikeVersion(e.version)) continue;
    if (typeof e.resolved === "string" && NPM_NON_REGISTRY_RE.test(e.resolved)) continue;
    const name = e.name ?? npmNameFromPath(path);
    // npm (v2+) writes dev/optional on every package it applies to, so their
    // absence is meaningful. v1 writes them too.
    const dev = e.dev === true ? true : e.devOptional === true ? null : false;
    pathToKey.set(path, graph.add(name, e.version, { dev, optional: e.optional === true || e.devOptional === true }));
  }

  const projectRoots = (path: string, e: NpmLockEntry) => {
    for (const [field, kind] of [["dependencies", "prod"], ["optionalDependencies", "prod"], ["peerDependencies", "prod"], ["devDependencies", "dev"]] as const) {
      for (const dep of Object.keys(asRecord(e[field]))) {
        const target = resolveNodeModule(allPaths, path, dep);
        const key = target ? pathToKey.get(target) : undefined;
        if (key) graph.root(key, kind);
      }
    }
  };

  for (const [path, e] of entries) {
    const isProject = !path.includes("node_modules/") && !e.link;
    if (isProject) {
      // "" is the root project; other non-node_modules paths are workspace
      // packages — the project's own code, so their dependencies are direct too.
      projectRoots(path, e);
      continue;
    }
    const from = pathToKey.get(path);
    if (!from) continue;
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"] as const) {
      for (const dep of Object.keys(asRecord(e[field]))) {
        const target = resolveNodeModule(allPaths, path, dep);
        const to = target ? pathToKey.get(target) : undefined;
        if (to) graph.edge(from, to);
      }
    }
  }

  // v1 (and any lockfile without a root entry): direct dependencies from package.json.
  if (!entries.has("")) {
    const manifest = readPackageJsonDeps(packageJson);
    if (manifest) projectRoots("", { dependencies: manifest.prod, devDependencies: manifest.dev });
  }

  return { ecosystem: "npm", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- Yarn: yarn.lock (classic v1 and berry v2+) --------------------------

/** "name@range" → [name, range]; the name may be scoped ("@a/b@^1"). */
function splitDescriptor(descriptor: string): [string, string] | null {
  const idx = descriptor.indexOf("@", 1);
  if (idx <= 0) return null;
  return [descriptor.slice(0, idx), descriptor.slice(idx + 1)];
}

const YARN_NON_REGISTRY_RANGE_RE = /^(git[+:]|github:|gitlab:|bitbucket:|file:|link:|portal:|exec:|workspace:|https?:)/i;

function rootYarnDeps(graph: DepGraph, lookup: (name: string, range: string) => string | undefined, manifest: NpmManifestDeps) {
  for (const [name, range] of Object.entries(manifest.prod)) {
    const key = lookup(name, range);
    if (key) graph.root(key, "prod");
  }
  for (const [name, range] of Object.entries(manifest.dev)) {
    const key = lookup(name, range);
    if (key) graph.root(key, "dev");
  }
}

function parseYarnClassic(raw: string, manifest: NpmManifestDeps | null, lockfile: string): LockfileParseResult {
  type Block = { descriptors: string[]; version?: string; deps: Array<[string, string]> };
  const blocks: Block[] = [];
  let current: Block | null = null;
  let inDeps = false;

  const tokens = (s: string) => (s.match(/"(?:[^"\\]|\\.)*"|\S+/g) ?? []).map((t) => (t.startsWith('"') ? t.slice(1, -1) : t));

  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    const text = line.trim();
    if (indent === 0) {
      if (!text.endsWith(":")) {
        current = null;
        continue;
      }
      current = {
        descriptors: text
          .slice(0, -1)
          .split(/,\s*/)
          .map((d) => d.trim().replace(/^"|"$/g, "")),
        deps: [],
      };
      blocks.push(current);
      inDeps = false;
    } else if (current && indent <= 2) {
      inDeps = text === "dependencies:" || text === "optionalDependencies:";
      const [k, v] = tokens(text);
      if (k === "version" && v) current.version = v;
    } else if (current && inDeps) {
      const [name, range] = tokens(text);
      if (name && range) current.deps.push([name, range]);
    }
  }
  if (blocks.length === 0 && raw.trim()) throw new LockfileParseError(lockfile, "no package entries found");

  const graph = new DepGraph("npm");
  const byDescriptor = new Map<string, string>();
  const blockKeys: Array<[Block, string]> = [];
  for (const b of blocks) {
    const first = splitDescriptor(b.descriptors[0] ?? "");
    if (!first || !looksLikeVersion(b.version)) continue;
    let [name, range] = first;
    if (range.startsWith("npm:")) {
      const inner = splitDescriptor(range.slice(4));
      if (!inner) continue;
      [name, range] = inner;
    }
    if (YARN_NON_REGISTRY_RANGE_RE.test(range)) continue;
    const key = graph.add(name, b.version);
    blockKeys.push([b, key]);
    for (const d of b.descriptors) byDescriptor.set(d, key);
  }
  const lookup = (name: string, range: string) => byDescriptor.get(`${name}@${range}`);
  for (const [b, key] of blockKeys) {
    for (const [name, range] of b.deps) {
      const to = lookup(name, range);
      if (to) graph.edge(key, to);
    }
  }
  if (manifest) rootYarnDeps(graph, lookup, manifest);
  return { ecosystem: "npm", lockfile, packages: graph.finalize(), hasGraph: true };
}

function parseYarnBerry(doc: YamlValue, manifest: NpmManifestDeps | null, lockfile: string): LockfileParseResult {
  if (!isYamlMap(doc)) throw new LockfileParseError(lockfile, "not a YAML mapping");
  const graph = new DepGraph("npm");
  const byDescriptor = new Map<string, string>();
  const workspaceDeps: Array<{ root: boolean; deps: Record<string, YamlValue> }> = [];
  const entries: Array<[string, Record<string, YamlValue>]> = [];

  for (const [descriptors, value] of Object.entries(doc)) {
    if (descriptors === "__metadata" || !isYamlMap(value)) continue;
    const resolution = typeof value.resolution === "string" ? value.resolution : "";
    const resolved = splitDescriptor(resolution);
    if (!resolved) continue;
    const [name, ref] = resolved;
    const deps = isYamlMap(value.dependencies) ? value.dependencies : {};

    if (ref.startsWith("workspace:")) {
      workspaceDeps.push({ root: ref === "workspace:.", deps });
      continue;
    }
    // npm: registry; patch: a local patch on top of a registry package (same name and version).
    const registry = ref.startsWith("npm:") || (ref.startsWith("patch:") && /npm%3A/i.test(ref));
    if (!registry || !looksLikeVersion(value.version)) continue;
    const key = graph.add(name, value.version);
    for (const d of descriptors.split(/,\s*/)) byDescriptor.set(d.trim(), key);
    entries.push([key, deps]);
  }

  // Berry descriptors carry the protocol ("lodash@npm:^4.17.0") but a
  // dependency's range usually doesn't ("^4.17.0"); try both.
  const lookup = (name: string, range: string) => byDescriptor.get(`${name}@${range}`) ?? byDescriptor.get(`${name}@npm:${range}`);
  for (const [from, deps] of entries) {
    for (const [name, range] of Object.entries(deps)) {
      const to = typeof range === "string" ? lookup(name, range) : undefined;
      if (to) graph.edge(from, to);
    }
  }

  // Workspace entries merge dependencies and devDependencies; package.json
  // (when given) says which of the root workspace's are dev-only.
  for (const ws of workspaceDeps) {
    for (const [name, range] of Object.entries(ws.deps)) {
      const key = typeof range === "string" ? lookup(name, range) : undefined;
      if (!key) continue;
      if (ws.root && manifest) graph.root(key, name in manifest.dev && !(name in manifest.prod) ? "dev" : "prod");
      else graph.root(key, "unknown");
    }
  }
  if (workspaceDeps.length === 0 && manifest) rootYarnDeps(graph, lookup, manifest);
  return { ecosystem: "npm", lockfile, packages: graph.finalize(), hasGraph: true };
}

/** yarn.lock, classic (v1) or berry (v2+, YAML with a `__metadata` block). */
export function parseYarnLock(raw: string, packageJson?: string | null, lockfile = "yarn.lock"): LockfileParseResult {
  const manifest = readPackageJsonDeps(packageJson);
  if (/^__metadata:/m.test(raw)) {
    const docs = parseYamlDocuments(raw);
    return parseYarnBerry(docs[docs.length - 1] ?? null, manifest, lockfile);
  }
  return parseYarnClassic(raw, manifest, lockfile);
}

// ---- pnpm: pnpm-lock.yaml (v5.x, v6, v9) ---------------------------------

/** "/@a/b/1.0.0_peer" (v5), "/@a/b@1.0.0(peer)" (v6), "@a/b@1.0.0(peer)" (v9) → name and version. */
function parsePnpmKey(key: string, v5: boolean): { name: string; version: string } | null {
  let k = key.replace(/\(.*$/, "");
  if (v5) {
    if (!k.startsWith("/")) {
      // "registry.example.com/foo/1.0.0" — a non-default registry host prefix.
      const slash = k.indexOf("/");
      if (slash < 0 || !k.slice(0, slash).includes(".")) return null;
      k = k.slice(slash);
    }
    k = k.slice(1);
    const idx = k.lastIndexOf("/");
    if (idx <= 0) return null;
    return { name: k.slice(0, idx), version: k.slice(idx + 1).split("_")[0] };
  }
  k = k.replace(/^\//, "");
  const idx = k.lastIndexOf("@");
  if (idx <= 0) return null;
  return { name: k.slice(0, idx), version: k.slice(idx + 1) };
}

/** A dependency reference ("4.17.21", "4.17.21(peer)", "4.17.21_peer", "/foo@1.0.0", "foo@1.0.0", "link:../x") → its package key. */
function resolvePnpmRef(depName: string, ref: string, v5: boolean): string | null {
  if (/^(link:|file:|workspace:)/.test(ref)) return null;
  if (ref.startsWith("/")) {
    const p = parsePnpmKey(ref, v5);
    return p && looksLikeVersion(p.version) ? packageKey(p.name, p.version) : null;
  }
  let r = ref.replace(/\(.*$/, "");
  if (v5) r = r.split("_")[0];
  const alias = r.lastIndexOf("@");
  if (alias > 0) {
    const version = r.slice(alias + 1);
    return looksLikeVersion(version) ? packageKey(r.slice(0, alias), version) : null;
  }
  return looksLikeVersion(r) ? packageKey(depName, r) : null;
}

export function parsePnpmLock(raw: string, lockfile = "pnpm-lock.yaml"): LockfileParseResult {
  const docs = parseYamlDocuments(raw).filter(isYamlMap);
  // pnpm 9 can prepend a second document (the package-manager "env"
  // lockfile); the project's own is the one with packages.
  const doc = [...docs].reverse().find((d) => d.packages !== undefined || d.importers !== undefined) ?? docs[docs.length - 1];
  if (!doc || doc.lockfileVersion === undefined) throw new LockfileParseError(lockfile, "no lockfileVersion");
  const major = parseFloat(String(doc.lockfileVersion));
  const v5 = major < 6;
  const graph = new DepGraph("npm");

  const packages = isYamlMap(doc.packages) ? doc.packages : {};
  const snapshots = isYamlMap(doc.snapshots) ? doc.snapshots : null;
  const depSources: Array<[string, { [key: string]: YamlValue }]> = [];

  for (const [key, value] of Object.entries(packages)) {
    const p = parsePnpmKey(key, v5);
    if (!p || !looksLikeVersion(p.version)) continue;
    const meta = isYamlMap(value) ? value : {};
    const resolution = typeof meta.resolution === "string" ? meta.resolution : "";
    if (/\b(directory|repo|commit):|tarball:\s*file:/.test(resolution)) continue;
    // v5/v6 mark dev-only (true) and prod-only (false) packages; a package
    // both need has no flag. v9 dropped the flag — derived from importers below.
    const dev = meta.dev === "true" ? true : meta.dev === "false" ? false : major < 9 ? false : undefined;
    const k = graph.add(p.name, p.version, { dev, optional: meta.optional === "true" });
    if (!snapshots) depSources.push([k, meta]);
  }
  if (snapshots) {
    for (const [key, value] of Object.entries(snapshots)) {
      const p = parsePnpmKey(key, false);
      if (!p || !isYamlMap(value)) continue;
      const k = packageKey(p.name, p.version);
      if (graph.nodes.has(k)) depSources.push([k, value]);
    }
  }
  for (const [from, meta] of depSources) {
    for (const field of ["dependencies", "optionalDependencies"]) {
      const deps = meta[field];
      if (!isYamlMap(deps)) continue;
      for (const [name, ref] of Object.entries(deps)) {
        const to = typeof ref === "string" ? resolvePnpmRef(name, ref, v5) : null;
        if (to && graph.nodes.has(to)) graph.edge(from, to);
      }
    }
  }

  const importers = isYamlMap(doc.importers) ? doc.importers : { ".": doc };
  for (const importer of Object.values(importers)) {
    if (!isYamlMap(importer)) continue;
    for (const [field, kind] of [["dependencies", "prod"], ["optionalDependencies", "prod"], ["devDependencies", "dev"]] as const) {
      const deps = importer[field];
      if (!isYamlMap(deps)) continue;
      for (const [name, spec] of Object.entries(deps)) {
        const ref = isYamlMap(spec) ? spec.version : spec;
        const key = typeof ref === "string" ? resolvePnpmRef(name, ref, v5) : null;
        if (key && graph.nodes.has(key)) graph.root(key, kind);
      }
    }
  }
  return { ecosystem: "npm", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- Python: poetry.lock, Pipfile.lock ------------------------------------

/** pyproject.toml's declared dependency names (PEP 503-normalised): Poetry sections, PEP 621 and PEP 735. */
export function readPyprojectDeps(raw: string | null | undefined): { prod: string[]; dev: string[] } | null {
  if (!raw) return null;
  let doc: TomlTable;
  try {
    doc = parseToml(raw);
  } catch {
    return null;
  }
  const prod = new Set<string>();
  const dev = new Set<string>();
  const pep508Name = (s: unknown) => (typeof s === "string" ? /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(s)?.[1] : undefined);

  const poetry = asRecord(asRecord(doc.tool).poetry);
  for (const name of Object.keys(asRecord(poetry.dependencies))) if (name.toLowerCase() !== "python") prod.add(normalisePyPiName(name));
  for (const name of Object.keys(asRecord(poetry["dev-dependencies"]))) dev.add(normalisePyPiName(name));
  for (const [group, def] of Object.entries(asRecord(poetry.group))) {
    for (const name of Object.keys(asRecord(asRecord(def).dependencies))) (group === "main" ? prod : dev).add(normalisePyPiName(name));
  }
  const project = asRecord(doc.project);
  for (const spec of Array.isArray(project.dependencies) ? project.dependencies : []) {
    const name = pep508Name(spec);
    if (name) prod.add(normalisePyPiName(name));
  }
  for (const specs of Object.values(asRecord(project["optional-dependencies"]))) {
    for (const spec of Array.isArray(specs) ? specs : []) {
      const name = pep508Name(spec);
      if (name) prod.add(normalisePyPiName(name));
    }
  }
  for (const specs of Object.values(asRecord(doc["dependency-groups"]))) {
    for (const spec of Array.isArray(specs) ? specs : []) {
      const name = pep508Name(spec);
      if (name) dev.add(normalisePyPiName(name));
    }
  }
  if (prod.size === 0 && dev.size === 0) return null;
  return { prod: [...prod], dev: [...dev].filter((n) => !prod.has(n)) };
}

const POETRY_NON_REGISTRY_SOURCES = new Set(["git", "directory", "file", "url"]);

/**
 * poetry.lock — every resolved package with its own dependencies. Which are
 * direct comes from `pyproject` (pyproject.toml) when given. Dev-only
 * comes from Poetry 1.x's `category` or Poetry 2.x's `groups`.
 */
export function parsePoetryLock(raw: string, pyproject?: string | null, lockfile = "poetry.lock"): LockfileParseResult {
  const doc = parseToml(raw);
  if (!Array.isArray(doc.package)) {
    if (/^\s*\[\[package\]\]/m.test(raw)) throw new LockfileParseError(lockfile, "could not read [[package]] entries");
    if (!doc.metadata) throw new LockfileParseError(lockfile, "no [[package]] or [metadata] section");
  }
  const graph = new DepGraph("PyPI");
  const byName = new Map<string, string[]>();
  const withDeps: Array<[string, Record<string, unknown>]> = [];

  for (const entry of Array.isArray(doc.package) ? doc.package : []) {
    const p = asRecord(entry);
    if (typeof p.name !== "string" || !looksLikeVersion(p.version)) continue;
    const sourceType = String(asRecord(p.source).type ?? "");
    if (POETRY_NON_REGISTRY_SOURCES.has(sourceType)) continue;
    const name = normalisePyPiName(p.name);
    let dev: boolean | undefined;
    if (p.category === "dev") dev = true;
    else if (p.category === "main") dev = false;
    else if (Array.isArray(p.groups)) dev = !p.groups.includes("main");
    const key = graph.add(name, p.version, { dev, optional: p.optional === true });
    byName.set(name, [...(byName.get(name) ?? []), key]);
    withDeps.push([key, asRecord(p.dependencies)]);
  }
  for (const [from, deps] of withDeps) {
    for (const dep of Object.keys(deps)) for (const to of byName.get(normalisePyPiName(dep)) ?? []) graph.edge(from, to);
  }
  const roots = readPyprojectDeps(pyproject);
  if (roots) {
    for (const name of roots.prod) for (const key of byName.get(name) ?? []) graph.root(key, "prod");
    for (const name of roots.dev) for (const key of byName.get(name) ?? []) graph.root(key, "dev");
  }
  return { ecosystem: "PyPI", lockfile, packages: graph.finalize(), hasGraph: true };
}

/** Pipfile.lock — a flat list (no graph, no direct/transitive split), `default` vs `develop`. */
export function parsePipfileLock(raw: string, lockfile = "Pipfile.lock"): LockfileParseResult {
  const lock = parseJson(raw, lockfile);
  if (!lock.default && !lock.develop) throw new LockfileParseError(lockfile, "no default or develop section");
  const graph = new DepGraph("PyPI");
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    for (const [name, value] of Object.entries(asRecord(lock[section]))) {
      const version = String(asRecord(value).version ?? "").replace(/^===?/, "");
      // No version: a git/path/editable entry — not a PyPI release.
      if (!looksLikeVersion(version)) continue;
      graph.add(normalisePyPiName(name), version, { dev });
    }
  }
  return { ecosystem: "PyPI", lockfile, packages: graph.finalize(), hasGraph: false };
}

// ---- Rust: Cargo.lock ------------------------------------------------------

const CRATES_IO_SOURCES = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);

/** Cargo.lock — packages without a `source` are the workspace's own crates; their dependencies are direct. */
export function parseCargoLock(raw: string, lockfile = "Cargo.lock"): LockfileParseResult {
  const doc = parseToml(raw);
  if (!Array.isArray(doc.package)) throw new LockfileParseError(lockfile, "no [[package]] entries");
  const graph = new DepGraph("crates.io");
  const byName = new Map<string, string[]>();
  const all: Array<{ key: string | null; deps: unknown[]; local: boolean }> = [];

  for (const entry of doc.package) {
    const p = asRecord(entry);
    if (typeof p.name !== "string" || typeof p.version !== "string") continue;
    const deps = Array.isArray(p.dependencies) ? p.dependencies : [];
    if (p.source === undefined) {
      all.push({ key: null, deps, local: true });
      continue;
    }
    // git sources and private registries aren't crates.io releases.
    if (!CRATES_IO_SOURCES.has(String(p.source)) || !looksLikeVersion(p.version)) continue;
    const key = graph.add(p.name, p.version);
    byName.set(p.name, [...(byName.get(p.name) ?? []), key]);
    all.push({ key, deps, local: false });
  }
  // "name", "name version" or "name version (source)".
  const resolve = (dep: unknown): string | undefined => {
    if (typeof dep !== "string") return undefined;
    const [name, version] = dep.split(" ");
    const candidates = byName.get(name) ?? [];
    if (version) return candidates.find((k) => k === packageKey(name, version));
    return candidates.length === 1 ? candidates[0] : undefined;
  };
  for (const { key, deps, local } of all) {
    for (const dep of deps) {
      const to = resolve(dep);
      if (!to) continue;
      // Cargo.lock doesn't separate [dev-dependencies]; a workspace crate's are "unknown".
      if (local) graph.root(to, "unknown");
      else if (key) graph.edge(key, to);
    }
  }
  return { ecosystem: "crates.io", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- PHP: composer.lock -----------------------------------------------------

const COMPOSER_PLATFORM_RE = /^(php(-64bit|-ipv6|-zts|-debug)?|hhvm|composer(-plugin-api|-runtime-api)?|ext-[\w-]+|lib-[\w-]+)$/i;

/** composer.lock — `packages` (runtime) and `packages-dev`; direct ones from composer.json when given. */
export function parseComposerLock(raw: string, composerJson?: string | null, lockfile = "composer.lock"): LockfileParseResult {
  const lock = parseJson(raw, lockfile);
  if (!Array.isArray(lock.packages) && !Array.isArray(lock["packages-dev"])) throw new LockfileParseError(lockfile, "no packages section");
  const graph = new DepGraph("Packagist");
  const byName = new Map<string, string>();
  const requires: Array<[string, Record<string, unknown>]> = [];

  for (const [section, dev] of [["packages", false], ["packages-dev", true]] as const) {
    for (const entry of Array.isArray(lock[section]) ? (lock[section] as unknown[]) : []) {
      const p = asRecord(entry);
      if (typeof p.name !== "string" || typeof p.version !== "string") continue;
      // Branch installs ("dev-main", "1.x-dev") aren't releases OSV.dev can place.
      const version = p.version.replace(/^v(?=\d)/, "");
      if (/^dev-|-dev$/.test(version) || !looksLikeVersion(version)) continue;
      const name = p.name.toLowerCase();
      const key = graph.add(name, version, { dev });
      byName.set(name, key);
      requires.push([key, asRecord(p.require)]);
    }
  }
  for (const [from, req] of requires) {
    for (const dep of Object.keys(req)) {
      if (COMPOSER_PLATFORM_RE.test(dep)) continue;
      const to = byName.get(dep.toLowerCase());
      if (to) graph.edge(from, to);
    }
  }
  if (composerJson) {
    try {
      const manifest = asRecord(JSON.parse(composerJson));
      for (const [field, kind] of [["require", "prod"], ["require-dev", "dev"]] as const) {
        for (const dep of Object.keys(asRecord(manifest[field]))) {
          const key = byName.get(dep.toLowerCase());
          if (key) graph.root(key, kind);
        }
      }
    } catch {
      // Unreadable composer.json: direct/transitive stays unknown.
    }
  }
  return { ecosystem: "Packagist", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- Go: go.sum (+ go.mod) ---------------------------------------------------

type GoModEntry = { path: string; version: string; indirect: boolean };

/** go.mod `require` and `replace` directives, any version shape (pseudo-versions, +incompatible). */
export function readGoMod(raw: string): { requires: GoModEntry[]; replaces: Map<string, { path: string; version: string } | null> } {
  const requires: GoModEntry[] = [];
  const replaces = new Map<string, { path: string; version: string } | null>();
  let block: "require" | "replace" | null = null;
  for (const rawLine of raw.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(rawLine);
    let line = rawLine.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (/^(require|replace)\s*\($/.test(line)) {
      block = line.startsWith("require") ? "require" : "replace";
      continue;
    }
    if (block && line === ")") {
      block = null;
      continue;
    }
    let kind = block;
    if (!kind) {
      const m = /^(require|replace)\s+(.*)$/.exec(line);
      if (!m) continue;
      kind = m[1] as "require" | "replace";
      line = m[2];
    }
    if (kind === "require") {
      const m = /^(\S+)\s+(v\S+)$/.exec(line);
      if (m) requires.push({ path: m[1], version: m[2], indirect });
    } else {
      const m = /^(\S+)(?:\s+\S+)?\s+=>\s+(\S+)(?:\s+(v\S+))?$/.exec(line);
      if (!m) continue;
      // A replacement with no version is a local directory: not a module OSV.dev knows.
      replaces.set(m[1], m[3] ? { path: m[2], version: m[3] } : null);
    }
  }
  return { requires, replaces };
}

const goVersion = (v: string) => v.replace(/^v/, "");

/**
 * go.sum — the modules whose content was downloaded for the build (lines
 * ending in "/go.mod" only hash a module's go.mod, for graph pruning, and
 * are ignored). go.sum may still list an older version a module was
 * upgraded from; Go's minimum version selection builds the highest, so
 * that's the one kept. go.mod, when given, names the selected version
 * outright (Go ≥ 1.17 lists every module the build uses) and which ones
 * are direct (no `// indirect`). go.sum records no graph.
 */
export function parseGoSum(raw: string, goMod?: string | null, lockfile = "go.sum"): LockfileParseResult {
  const highest = new Map<string, string>();
  let lines = 0;
  for (const line of raw.split(/\r?\n/)) {
    const m = /^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:\S+$/.exec(line.trim());
    if (!m) continue;
    lines++;
    if (m[3]) continue;
    const prev = highest.get(m[1]);
    if (!prev || (compareEcosystemVersions("Go", goVersion(m[2]), goVersion(prev)) ?? 0) > 0) highest.set(m[1], m[2]);
  }
  if (lines === 0 && raw.trim()) throw new LockfileParseError(lockfile, "no module hash lines");

  const mod = goMod ? readGoMod(goMod) : null;
  const graph = new DepGraph("Go");
  const selected = new Map(highest);
  for (const r of mod?.requires ?? []) selected.set(r.path, r.version);
  if (mod) graph.roots = new Map();

  for (const [path, version] of [...selected].sort()) {
    let name = path;
    let v = version;
    if (mod?.replaces.has(path)) {
      const rep = mod.replaces.get(path);
      if (!rep) continue;
      name = rep.path;
      v = rep.version;
    }
    if (!looksLikeVersion(goVersion(v))) continue;
    const key = graph.add(name, goVersion(v));
    const req = mod?.requires.find((r) => r.path === path);
    if (req && !req.indirect) graph.root(key, "unknown");
  }
  return { ecosystem: "Go", lockfile, packages: graph.finalize().map((p) => ({ ...p, introducedVia: undefined })), hasGraph: false };
}

// ---- Ruby: Gemfile.lock -----------------------------------------------------

/**
 * Gemfile.lock — GEM sections are rubygems releases; GIT and PATH gems are
 * walked through (their dependencies are real gems) but not reported.
 * Bundler doesn't record groups in the lockfile, so dev is unknown.
 */
export function parseGemfileLock(raw: string, lockfile = "Gemfile.lock"): LockfileParseResult {
  const graph = new DepGraph("RubyGems");
  const byName = new Map<string, string>();
  const specDeps: Array<[string, string[]]> = [];
  const declared: string[] = [];
  let section = "";
  let currentSpec: [string, string[]] | null = null;

  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const text = line.trim();
    if (indent === 0) {
      section = text;
      currentSpec = null;
      continue;
    }
    if (section === "DEPENDENCIES" && indent === 2) {
      declared.push(text.split(/\s/)[0].replace(/!$/, ""));
      continue;
    }
    if (!["GEM", "GIT", "PATH", "PLUGIN SOURCE"].includes(section)) continue;
    const m = /^([^\s(]+)(?:\s+\(([^)]*)\))?$/.exec(text);
    if (indent === 4 && m && m[2]) {
      // A platform build ("1.13.10-x86_64-linux") is the same release; RubyGems prereleases use ".", not "-".
      const version = m[2].split("-")[0];
      const hidden = section !== "GEM";
      if (!hidden && !looksLikeVersion(version)) {
        currentSpec = null;
        continue;
      }
      const key = graph.add(m[1], version, { hidden });
      if (!hidden || !byName.has(m[1])) byName.set(m[1], key);
      currentSpec = [key, []];
      specDeps.push(currentSpec);
    } else if (indent === 6 && m && currentSpec) {
      currentSpec[1].push(m[1]);
    }
  }
  if (specDeps.length === 0 && !/^GEM$/m.test(raw) && raw.trim()) throw new LockfileParseError(lockfile, "no GEM section");

  for (const [from, deps] of specDeps) for (const dep of deps) {
    const to = byName.get(dep);
    if (to) graph.edge(from, to);
  }
  graph.roots = new Map();
  for (const name of declared) {
    const key = byName.get(name);
    if (key) graph.root(key, "unknown");
  }
  return { ecosystem: "RubyGems", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- .NET: packages.lock.json ------------------------------------------------

/** NuGet packages.lock.json — per target framework; "Direct" vs "Transitive"/"CentralTransitive"; "Project" references are walked, not reported. */
export function parseNugetPackagesLock(raw: string, lockfile = "packages.lock.json"): LockfileParseResult {
  const lock = parseJson(raw, lockfile);
  if (!lock.dependencies || typeof lock.dependencies !== "object") throw new LockfileParseError(lockfile, "no dependencies section");
  const graph = new DepGraph("NuGet");
  graph.roots = new Map();

  for (const framework of Object.values(asRecord(lock.dependencies))) {
    const pkgs = asRecord(framework);
    const keyByName = new Map<string, string>();
    for (const [name, value] of Object.entries(pkgs)) {
      const e = asRecord(value);
      if (e.type === "Project") {
        keyByName.set(name.toLowerCase(), graph.add(name, "project", { hidden: true }));
        continue;
      }
      if (!looksLikeVersion(e.resolved)) continue;
      const key = graph.add(name, e.resolved);
      keyByName.set(name.toLowerCase(), key);
      if (e.type === "Direct") graph.root(key, "unknown");
    }
    for (const [name, value] of Object.entries(pkgs)) {
      const from = keyByName.get(name.toLowerCase());
      if (!from) continue;
      for (const dep of Object.keys(asRecord(asRecord(value).dependencies))) {
        const to = keyByName.get(dep.toLowerCase());
        if (to) graph.edge(from, to);
      }
    }
  }
  return { ecosystem: "NuGet", lockfile, packages: graph.finalize(), hasGraph: true };
}

// ---- Gradle: gradle.lockfile -------------------------------------------------

/**
 * gradle.lockfile — "group:artifact:version=configuration,...". No graph or
 * direct/transitive split. A package only on test (or other build-time)
 * configurations is dev-only; one on a non-test compile/runtime classpath
 * ships.
 */
export function parseGradleLockfile(raw: string, lockfile = "gradle.lockfile"): LockfileParseResult {
  const graph = new DepGraph("Maven");
  let seen = 0;
  for (const line of raw.split(/\r?\n/)) {
    const text = line.trim();
    if (!text || text.startsWith("#")) continue;
    const m = /^([^:=\s]+):([^:=\s]+):([^:=\s]+)=(.*)$/.exec(text);
    if (!m) continue;
    seen++;
    if (!looksLikeVersion(m[3])) continue;
    const configurations = m[4].split(",").map((c) => c.trim());
    const ships = configurations.some((c) => /(compile|runtime)Classpath$/i.test(c) && !/test/i.test(c));
    graph.add(`${m[1]}:${m[2]}`, m[3], { dev: !ships });
  }
  if (seen === 0 && !/^empty=/m.test(raw) && raw.trim() && !raw.split(/\r?\n/).every((l) => !l.trim() || l.trim().startsWith("#"))) {
    throw new LockfileParseError(lockfile, "no dependency lines");
  }
  return { ecosystem: "Maven", lockfile, packages: graph.finalize(), hasGraph: false };
}

// ---- Registry --------------------------------------------------------------

/** Companion manifest a lockfile parser can use to tell direct from transitive. */
export type LockfileDescriptor = {
  file: string;
  ecosystem: OsvEcosystem;
  companion?: string;
  parse: (content: string, companionContent?: string | null) => LockfileParseResult;
};

/**
 * Every supported lockfile, in preference order within an ecosystem: when a
 * repo has two for the same ecosystem (say package-lock.json and yarn.lock),
 * the first is used. Exported so a pull-request check can parse the same
 * files the scan does.
 */
export const LOCKFILES: LockfileDescriptor[] = [
  { file: "npm-shrinkwrap.json", ecosystem: "npm", companion: "package.json", parse: (c, m) => parseNpmPackageLock(c, m, "npm-shrinkwrap.json") },
  { file: "package-lock.json", ecosystem: "npm", companion: "package.json", parse: (c, m) => parseNpmPackageLock(c, m) },
  { file: "pnpm-lock.yaml", ecosystem: "npm", parse: (c) => parsePnpmLock(c) },
  { file: "yarn.lock", ecosystem: "npm", companion: "package.json", parse: (c, m) => parseYarnLock(c, m) },
  { file: "poetry.lock", ecosystem: "PyPI", companion: "pyproject.toml", parse: (c, m) => parsePoetryLock(c, m) },
  { file: "Pipfile.lock", ecosystem: "PyPI", parse: (c) => parsePipfileLock(c) },
  { file: "composer.lock", ecosystem: "Packagist", companion: "composer.json", parse: (c, m) => parseComposerLock(c, m) },
  { file: "go.sum", ecosystem: "Go", companion: "go.mod", parse: (c, m) => parseGoSum(c, m) },
  { file: "gradle.lockfile", ecosystem: "Maven", parse: (c) => parseGradleLockfile(c) },
  { file: "Gemfile.lock", ecosystem: "RubyGems", parse: (c) => parseGemfileLock(c) },
  { file: "Cargo.lock", ecosystem: "crates.io", parse: (c) => parseCargoLock(c) },
  { file: "packages.lock.json", ecosystem: "NuGet", parse: (c) => parseNugetPackagesLock(c) },
];

/**
 * Parses a lockfile by its file name (the basename: "package-lock.json",
 * "Cargo.lock", ...). `companion` is the matching manifest's content when
 * available (see LOCKFILES). Throws LockfileParseError for malformed content
 * and for an unsupported file name.
 */
export function parseLockfile(fileName: string, content: string, companion?: string | null): LockfileParseResult {
  const descriptor = LOCKFILES.find((d) => d.file === fileName);
  if (!descriptor) throw new LockfileParseError(fileName, "not a supported lockfile");
  return descriptor.parse(content, companion);
}
