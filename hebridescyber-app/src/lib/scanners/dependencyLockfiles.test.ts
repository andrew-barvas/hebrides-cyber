import { describe, it, expect } from "vitest";
import {
  LOCKFILES,
  LockfileParseError,
  parseCargoLock,
  parseComposerLock,
  parseGemfileLock,
  parseGoSum,
  parseGradleLockfile,
  parseLockfile,
  parseNpmPackageLock,
  parseNugetPackagesLock,
  parsePipfileLock,
  parsePnpmLock,
  parsePoetryLock,
  parseYarnLock,
  readPyprojectDeps,
  type LockfilePackage,
} from "./dependencyLockfiles";

// Fixtures are small and synthetic: made-up package names and versions in
// each format's real shape.

const byName = (pkgs: LockfilePackage[], name: string, version?: string) => {
  const found = pkgs.find((p) => p.name === name && (!version || p.version === version));
  if (!found) throw new Error(`no ${name}${version ? `@${version}` : ""} in ${pkgs.map((p) => `${p.name}@${p.version}`).join(", ")}`);
  return found;
};

const PACKAGE_JSON = JSON.stringify({
  name: "demo-app",
  dependencies: { "web-frame": "^4.0.0", "@acme/util": "^1.0.0" },
  devDependencies: { "test-runner": "^2.0.0" },
});

describe("parseNpmPackageLock — v2/v3", () => {
  const lock = JSON.stringify({
    name: "demo-app",
    lockfileVersion: 3,
    packages: {
      "": { name: "demo-app", dependencies: { "web-frame": "^4.0.0", "@acme/util": "^1.0.0" }, devDependencies: { "test-runner": "^2.0.0" } },
      "node_modules/web-frame": { version: "4.1.0", resolved: "https://registry.npmjs.org/web-frame/-/web-frame-4.1.0.tgz", dependencies: { "body-reader": "^1.0.0", "deep-merge": "^1.0.0" } },
      "node_modules/body-reader": { version: "1.2.0", dependencies: { "deep-merge": "^2.0.0" } },
      "node_modules/body-reader/node_modules/deep-merge": { version: "2.0.1" },
      "node_modules/deep-merge": { version: "1.0.5" },
      "node_modules/@acme/util": { version: "1.3.0" },
      "node_modules/test-runner": { version: "2.2.0", dev: true, dependencies: { "deep-merge": "^1.0.0", "glob-lite": "^1.0.0" } },
      "node_modules/glob-lite": { version: "1.0.0", dev: true },
      "node_modules/fs-watch": { version: "1.0.0", optional: true },
      "node_modules/my-alias": { name: "real-pkg", version: "3.0.0" },
      "node_modules/from-git": { version: "1.0.0", resolved: "git+ssh://git@github.com/example/from-git.git#abc" },
      "node_modules/ws-lib": { resolved: "packages/ws-lib", link: true },
      "packages/ws-lib": { name: "ws-lib", version: "0.1.0", dependencies: { "@acme/util": "^1.0.0" } },
    },
  });
  const { packages, hasGraph } = parseNpmPackageLock(lock);

  it("reads every installed package, nested copies included", () => {
    expect(hasGraph).toBe(true);
    expect(packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(
      ["@acme/util@1.3.0", "body-reader@1.2.0", "deep-merge@1.0.5", "deep-merge@2.0.1", "fs-watch@1.0.0", "glob-lite@1.0.0", "real-pkg@3.0.0", "test-runner@2.2.0", "web-frame@4.1.0"].sort()
    );
  });

  it("tells direct from transitive and records how a package came in", () => {
    expect(byName(packages, "web-frame")).toMatchObject({ direct: true, dev: false, introducedVia: [] });
    expect(byName(packages, "deep-merge", "2.0.1")).toMatchObject({ direct: false, introducedVia: ["web-frame@4.1.0", "body-reader@1.2.0"] });
    expect(byName(packages, "deep-merge", "1.0.5")).toMatchObject({ direct: false, introducedVia: ["web-frame@4.1.0"] });
    expect(byName(packages, "web-frame").dependsOn).toEqual(["body-reader@1.2.0", "deep-merge@1.0.5"]);
  });

  it("uses npm's dev/optional flags", () => {
    expect(byName(packages, "test-runner")).toMatchObject({ direct: true, dev: true });
    expect(byName(packages, "glob-lite")).toMatchObject({ direct: false, dev: true, introducedVia: ["test-runner@2.2.0"] });
    expect(byName(packages, "fs-watch").optional).toBe(true);
  });

  it("uses an alias's real name and skips git and workspace links", () => {
    expect(packages.some((p) => p.name === "my-alias")).toBe(false);
    expect(packages.some((p) => p.name === "from-git" || p.name === "ws-lib")).toBe(false);
  });

  it("treats a workspace package's dependencies as direct", () => {
    expect(byName(packages, "@acme/util").direct).toBe(true);
  });

  it("throws on malformed content", () => {
    expect(() => parseNpmPackageLock("{not json")).toThrow(LockfileParseError);
    expect(() => parseNpmPackageLock("{}")).toThrow(/no `packages`/);
  });
});

describe("parseNpmPackageLock — v1", () => {
  const lock = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      "web-frame": { version: "4.1.0", requires: { "body-reader": "^1.0.0" } },
      "body-reader": { version: "1.2.0", requires: { "deep-merge": "^2.0.0" }, dependencies: { "deep-merge": { version: "2.0.1" } } },
      "deep-merge": { version: "1.0.5" },
      "@acme/util": { version: "1.3.0" },
      "test-runner": { version: "2.2.0", dev: true },
      "aliased": { version: "npm:real-pkg@3.0.0" },
    },
  });

  it("reads the nested tree; direct deps need package.json", () => {
    const without = parseNpmPackageLock(lock).packages;
    expect(byName(without, "web-frame").direct).toBeNull();
    const withManifest = parseNpmPackageLock(lock, PACKAGE_JSON).packages;
    expect(byName(withManifest, "web-frame")).toMatchObject({ direct: true, introducedVia: [] });
    expect(byName(withManifest, "deep-merge", "2.0.1")).toMatchObject({ direct: false, introducedVia: ["web-frame@4.1.0", "body-reader@1.2.0"] });
    expect(byName(withManifest, "test-runner")).toMatchObject({ direct: true, dev: true });
    expect(byName(withManifest, "real-pkg").version).toBe("3.0.0");
  });
});

describe("parseYarnLock — classic v1", () => {
  const lock = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@acme/util@^1.0.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/@acme/util/-/util-1.3.0.tgz#abc"
  integrity sha512-AAAA

body-reader@^1.0.0:
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/body-reader/-/body-reader-1.2.0.tgz#def"
  dependencies:
    deep-merge "^1.0.0"

deep-merge@^1.0.0, deep-merge@^1.0.3:
  version "1.0.5"

test-runner@^2.0.0:
  version "2.2.0"
  dependencies:
    deep-merge "^1.0.3"

web-frame@^4.0.0:
  version "4.1.0"
  dependencies:
    body-reader "^1.0.0"
  optionalDependencies:
    "@acme/util" "^1.0.0"

from-git@git+https://github.com/example/from-git.git:
  version "1.0.0"
`;

  it("reads entries, resolving dependencies through descriptors", () => {
    const { packages } = parseYarnLock(lock, PACKAGE_JSON);
    expect(packages.map((p) => p.name).sort()).toEqual(["@acme/util", "body-reader", "deep-merge", "test-runner", "web-frame"]);
    expect(byName(packages, "deep-merge")).toMatchObject({ direct: false, dev: false, introducedVia: ["web-frame@4.1.0", "body-reader@1.2.0"] });
    expect(byName(packages, "test-runner")).toMatchObject({ direct: true, dev: true });
    expect(byName(packages, "web-frame").dependsOn).toEqual(["@acme/util@1.3.0", "body-reader@1.2.0"]);
  });

  it("leaves direct unknown without package.json", () => {
    expect(byName(parseYarnLock(lock).packages, "web-frame").direct).toBeNull();
  });
});

describe("parseYarnLock — berry", () => {
  const lock = `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"@acme/util@npm:^1.0.0":
  version: 1.3.0
  resolution: "@acme/util@npm:1.3.0"
  checksum: 10c0/aaaa
  languageName: node
  linkType: hard

"body-reader@npm:^1.0.0":
  version: 1.2.0
  resolution: "body-reader@npm:1.2.0"
  dependencies:
    deep-merge: "npm:^1.0.0"
  languageName: node
  linkType: hard

"deep-merge@npm:^1.0.0":
  version: 1.0.5
  resolution: "deep-merge@npm:1.0.5"
  languageName: node
  linkType: hard

"demo-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo-app@workspace:."
  dependencies:
    "@acme/util": "npm:^1.0.0"
    test-runner: "npm:^2.0.0"
    web-frame: "npm:^4.0.0"
  languageName: unknown
  linkType: soft

"patched-lib@patch:patched-lib@npm%3A1.0.0#~/.yarn/patches/fix.patch::version=1.0.0&hash=abc":
  version: 1.0.0
  resolution: "patched-lib@patch:patched-lib@npm%3A1.0.0#~/.yarn/patches/fix.patch::version=1.0.0&hash=abc"
  languageName: node
  linkType: hard

"test-runner@npm:^2.0.0":
  version: 2.2.0
  resolution: "test-runner@npm:2.2.0"
  languageName: node
  linkType: hard

"web-frame@npm:^4.0.0":
  version: 4.1.0
  resolution: "web-frame@npm:4.1.0"
  dependencies:
    body-reader: "npm:^1.0.0"
  languageName: node
  linkType: hard
`;

  it("reads registry entries and the workspace's dependencies as direct", () => {
    const { packages } = parseYarnLock(lock, PACKAGE_JSON);
    expect(packages.map((p) => p.name).sort()).toEqual(["@acme/util", "body-reader", "deep-merge", "patched-lib", "test-runner", "web-frame"]);
    expect(byName(packages, "web-frame")).toMatchObject({ direct: true, dev: false });
    expect(byName(packages, "test-runner")).toMatchObject({ direct: true, dev: true });
    expect(byName(packages, "deep-merge")).toMatchObject({ direct: false, introducedVia: ["web-frame@4.1.0", "body-reader@1.2.0"] });
  });

  it("without package.json, workspace deps are direct but dev is unknown", () => {
    expect(byName(parseYarnLock(lock).packages, "test-runner")).toMatchObject({ direct: true, dev: null });
  });
});

describe("parsePnpmLock", () => {
  it("reads lockfile v9 (importers + packages + snapshots)", () => {
    const lock = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      web-frame:
        specifier: ^4.0.0
        version: 4.1.0
      shared-lib:
        specifier: workspace:*
        version: link:packages/shared
    devDependencies:
      test-runner:
        specifier: ^2.0.0
        version: 2.2.0(peer-thing@1.0.0)

packages:

  '@acme/util@1.3.0':
    resolution: {integrity: sha512-AAAA}

  body-reader@1.2.0:
    resolution: {integrity: sha512-BBBB}

  peer-thing@1.0.0:
    resolution: {integrity: sha512-CCCC}

  test-runner@2.2.0:
    resolution: {integrity: sha512-DDDD}
    peerDependencies:
      peer-thing: ^1.0.0

  web-frame@4.1.0:
    resolution: {integrity: sha512-EEEE}
    engines: {node: '>=18'}

snapshots:

  '@acme/util@1.3.0': {}

  body-reader@1.2.0:
    dependencies:
      '@acme/util': 1.3.0

  peer-thing@1.0.0: {}

  test-runner@2.2.0(peer-thing@1.0.0):
    dependencies:
      peer-thing: 1.0.0
    transitivePeerDependencies:
      - supports-color

  web-frame@4.1.0:
    dependencies:
      body-reader: 1.2.0
`;
    const { packages } = parsePnpmLock(lock);
    expect(packages.map((p) => p.name).sort()).toEqual(["@acme/util", "body-reader", "peer-thing", "test-runner", "web-frame"]);
    expect(byName(packages, "@acme/util")).toMatchObject({ direct: false, dev: false, introducedVia: ["web-frame@4.1.0", "body-reader@1.2.0"] });
    expect(byName(packages, "test-runner")).toMatchObject({ direct: true, dev: true });
    expect(byName(packages, "peer-thing")).toMatchObject({ direct: false, dev: true });
  });

  it("reads lockfile v6 (with dev flags)", () => {
    const lock = `lockfileVersion: '6.0'

dependencies:
  web-frame:
    specifier: ^4.0.0
    version: 4.1.0

devDependencies:
  test-runner:
    specifier: ^2.0.0
    version: 2.2.0

packages:

  /body-reader@1.2.0:
    resolution: {integrity: sha512-BBBB}
    dev: false

  /test-runner@2.2.0:
    resolution: {integrity: sha512-DDDD}
    dev: true

  /web-frame@4.1.0:
    resolution: {integrity: sha512-EEEE}
    dependencies:
      body-reader: 1.2.0
    dev: false

  /local-thing@file:../local:
    resolution: {directory: ../local, type: directory}
`;
    const { packages } = parsePnpmLock(lock);
    expect(packages.map((p) => p.name).sort()).toEqual(["body-reader", "test-runner", "web-frame"]);
    expect(byName(packages, "body-reader")).toMatchObject({ direct: false, dev: false, introducedVia: ["web-frame@4.1.0"] });
    expect(byName(packages, "test-runner")).toMatchObject({ direct: true, dev: true });
  });

  it("reads lockfile v5 keys and peer suffixes", () => {
    const lock = `lockfileVersion: 5.4

specifiers:
  '@acme/util': ^1.0.0

dependencies:
  '@acme/util': 1.3.0_peer-thing@1.0.0

packages:

  /@acme/util/1.3.0_peer-thing@1.0.0:
    resolution: {integrity: sha512-AAAA}
    dependencies:
      peer-thing: 1.0.0
    dev: false

  /peer-thing/1.0.0:
    resolution: {integrity: sha512-CCCC}
    dev: false
`;
    const { packages } = parsePnpmLock(lock);
    expect(byName(packages, "@acme/util")).toMatchObject({ version: "1.3.0", direct: true });
    expect(byName(packages, "peer-thing")).toMatchObject({ direct: false, introducedVia: ["@acme/util@1.3.0"] });
  });

  it("throws without a lockfileVersion", () => {
    expect(() => parsePnpmLock("packages: {}\n")).toThrow(LockfileParseError);
  });
});

describe("Python lockfiles", () => {
  const poetry = `# This file is automatically @generated by Poetry 1.8.2 and should not be changed by hand.

[[package]]
name = "http-client"
version = "2.28.0"
description = "Demo HTTP client"
optional = false
python-versions = ">=3.7"
files = [
    {file = "http_client-2.28.0-py3-none-any.whl", hash = "sha256:aaaa"},
    {file = "http_client-2.28.0.tar.gz", hash = "sha256:bbbb"},
]

[package.dependencies]
url-tools = ">=1.21.1,<1.27"
Cert_Store = {version = ">=2017.4.17", markers = "python_version >= \\"3.7\\""}

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[[package]]
name = "url-tools"
version = "1.26.5"
description = "URL helpers"
optional = false
python-versions = "*"
files = []

[[package]]
name = "cert-store"
version = "2022.12.7"
description = "Certificates"
optional = false
python-versions = ">=3.6"
files = []

[[package]]
name = "test-kit"
version = "7.0.0"
description = "Testing"
category = "dev"
optional = false
python-versions = ">=3.7"
files = []

[[package]]
name = "local-lib"
version = "0.1.0"
description = "Local"
optional = false
python-versions = "*"
files = []
develop = true

[package.source]
type = "directory"
url = "../local-lib"

[metadata]
lock-version = "2.0"
python-versions = "^3.10"
content-hash = "cccc"
`;
  const pyproject = `[tool.poetry]
name = "demo-app"

[tool.poetry.dependencies]
python = "^3.10"
http-client = "^2.28"

[tool.poetry.group.dev.dependencies]
Test_Kit = "^7.0"
`;

  it("poetry.lock: graph, dev category, non-registry sources skipped", () => {
    const { packages } = parsePoetryLock(poetry, pyproject);
    expect(packages.map((p) => p.name).sort()).toEqual(["cert-store", "http-client", "test-kit", "url-tools"]);
    expect(byName(packages, "http-client")).toMatchObject({ direct: true, introducedVia: [] });
    expect(byName(packages, "cert-store")).toMatchObject({ direct: false, introducedVia: ["http-client@2.28.0"] });
    expect(byName(packages, "test-kit")).toMatchObject({ direct: true, dev: true });
    expect(byName(parsePoetryLock(poetry).packages, "http-client").direct).toBeNull();
  });

  it("poetry 2.x groups mark dev-only packages", () => {
    const lock = `[[package]]
name = "lint-tool"
version = "1.0.0"
groups = ["dev"]
files = []

[[package]]
name = "core-lib"
version = "2.0.0"
groups = ["main", "dev"]
files = []
`;
    const { packages } = parsePoetryLock(lock);
    expect(byName(packages, "lint-tool").dev).toBe(true);
    expect(byName(packages, "core-lib").dev).toBe(false);
  });

  it("readPyprojectDeps reads Poetry, PEP 621 and PEP 735 declarations", () => {
    expect(readPyprojectDeps(pyproject)).toEqual({ prod: ["http-client"], dev: ["test-kit"] });
    const pep621 = `[project]
name = "demo"
dependencies = [
  "Http_Client>=2.0",
  "url-tools[extra] ; python_version > '3.8'",
]

[dependency-groups]
dev = ["test-kit>=7"]
`;
    expect(readPyprojectDeps(pep621)).toEqual({ prod: ["http-client", "url-tools"], dev: ["test-kit"] });
    expect(readPyprojectDeps("[tool.black]\nline-length = 100\n")).toBeNull();
  });

  it("Pipfile.lock: default vs develop, git entries skipped", () => {
    const lock = JSON.stringify({
      _meta: { hash: { sha256: "x" } },
      default: { "http-client": { hashes: [], version: "==2.28.0" }, "from-git": { git: "https://example.com/x.git", ref: "abc" } },
      develop: { "test-kit": { version: "==7.0.0" } },
    });
    const r = parsePipfileLock(lock);
    expect(r.hasGraph).toBe(false);
    expect(r.packages).toEqual([
      { ecosystem: "PyPI", name: "http-client", version: "2.28.0", direct: null, dev: false },
      { ecosystem: "PyPI", name: "test-kit", version: "7.0.0", direct: null, dev: true },
    ]);
    expect(() => parsePipfileLock("{}")).toThrow(LockfileParseError);
  });
});

describe("parseCargoLock", () => {
  const lock = `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
 "serde-lite",
 "byte-tools 1.0.5",
]

[[package]]
name = "byte-tools"
version = "1.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "byte-tools"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde-lite"
version = "1.0.150"
source = "sparse+https://index.crates.io/"
dependencies = [
 "byte-tools 0.9.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/example/forked?branch=main#abc"
`;
  it("reads crates.io packages; workspace crates' deps are direct", () => {
    const { packages } = parseCargoLock(lock);
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["byte-tools@0.9.0", "byte-tools@1.0.5", "serde-lite@1.0.150"]);
    expect(byName(packages, "serde-lite")).toMatchObject({ direct: true, dev: null });
    expect(byName(packages, "byte-tools", "0.9.0")).toMatchObject({ direct: false, introducedVia: ["serde-lite@1.0.150"] });
    expect(() => parseCargoLock("version = 3\n")).toThrow(LockfileParseError);
  });
});

describe("parseComposerLock", () => {
  const lock = JSON.stringify({
    "content-hash": "x",
    packages: [
      { name: "acme/http-kernel", version: "v5.4.0", require: { php: ">=7.2", "acme/event-bus": "^5.0", "ext-json": "*" } },
      { name: "acme/event-bus", version: "5.1.2" },
      { name: "acme/branch-dep", version: "dev-main" },
    ],
    "packages-dev": [{ name: "acme/test-kit", version: "9.5.0", require: { "acme/event-bus": "^5.0" } }],
  });
  const composerJson = JSON.stringify({ require: { php: "^8.1", "acme/http-kernel": "^5.4" }, "require-dev": { "acme/test-kit": "^9.5" } });

  it("reads packages and packages-dev, strips v, skips branch installs", () => {
    const { packages } = parseComposerLock(lock, composerJson);
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["acme/event-bus@5.1.2", "acme/http-kernel@5.4.0", "acme/test-kit@9.5.0"]);
    expect(byName(packages, "acme/http-kernel")).toMatchObject({ direct: true, dev: false });
    expect(byName(packages, "acme/event-bus")).toMatchObject({ direct: false, introducedVia: ["acme/http-kernel@5.4.0"] });
    expect(byName(packages, "acme/test-kit")).toMatchObject({ direct: true, dev: true });
    expect(byName(parseComposerLock(lock).packages, "acme/event-bus").direct).toBeNull();
  });
});

describe("parseGoSum", () => {
  const sum = `example.com/router v1.7.0 h1:aaaa=
example.com/router v1.7.0/go.mod h1:bbbb=
example.com/router v1.8.0 h1:cccc=
example.com/router v1.8.0/go.mod h1:dddd=
example.com/only-gomod v0.3.0/go.mod h1:eeee=
example.com/text v0.3.7 h1:ffff=
example.com/old v2.0.0+incompatible h1:gggg=
example.com/replaced v1.0.0 h1:hhhh=
`;
  const goMod = `module example.com/app

go 1.21

require (
	example.com/router v1.8.0
	example.com/text v0.3.7 // indirect
	example.com/pseudo v0.0.0-20210101000000-abcdef123456
)

replace example.com/replaced => ../local/replaced
`;

  it("keeps the highest built version, skips /go.mod-only lines", () => {
    const { packages, hasGraph } = parseGoSum(sum);
    expect(hasGraph).toBe(false);
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["example.com/old@2.0.0+incompatible", "example.com/replaced@1.0.0", "example.com/router@1.8.0", "example.com/text@0.3.7"]);
    expect(packages.every((p) => p.direct === null)).toBe(true);
  });

  it("with go.mod: direct vs indirect, go.mod-only modules, local replaces dropped", () => {
    const { packages } = parseGoSum(sum, goMod);
    expect(byName(packages, "example.com/router").direct).toBe(true);
    expect(byName(packages, "example.com/text").direct).toBe(false);
    expect(byName(packages, "example.com/pseudo").version).toBe("0.0.0-20210101000000-abcdef123456");
    expect(packages.some((p) => p.name === "example.com/replaced")).toBe(false);
    expect(byName(packages, "example.com/old").direct).toBe(false);
  });

  it("throws on content with no hash lines", () => {
    expect(() => parseGoSum("not a go.sum\n")).toThrow(LockfileParseError);
  });
});

describe("parseGemfileLock", () => {
  const lock = `GIT
  remote: https://github.com/example/forked-gem.git
  revision: abc123
  specs:
    forked-gem (0.5.0)
      rack-lite (>= 2.0)

GEM
  remote: https://rubygems.org/
  specs:
    html-parse (1.13.10-x86_64-linux)
      racc-lite (~> 1.4)
    html-parse (1.13.10-arm64-darwin)
      racc-lite (~> 1.4)
    rack-lite (2.2.4)
    racc-lite (1.6.1)
    web-kit (7.0.4)
      html-parse (>= 1.6)
      rack-lite (~> 2.2)

PLATFORMS
  arm64-darwin
  x86_64-linux

DEPENDENCIES
  forked-gem!
  web-kit (~> 7.0.4)

BUNDLED WITH
   2.3.26
`;
  it("reads GEM specs, strips platforms, walks through git gems", () => {
    const { packages } = parseGemfileLock(lock);
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["html-parse@1.13.10", "racc-lite@1.6.1", "rack-lite@2.2.4", "web-kit@7.0.4"]);
    expect(byName(packages, "web-kit")).toMatchObject({ direct: true, introducedVia: [] });
    expect(byName(packages, "racc-lite")).toMatchObject({ direct: false, introducedVia: ["web-kit@7.0.4", "html-parse@1.13.10"] });
    expect(byName(packages, "rack-lite")).toMatchObject({ direct: false, introducedVia: ["forked-gem@0.5.0"] });
  });
});

describe("parseNugetPackagesLock", () => {
  const lock = JSON.stringify({
    version: 1,
    dependencies: {
      "net8.0": {
        "Demo.Json": { type: "Direct", requested: "[13.0.1, )", resolved: "13.0.1", contentHash: "x" },
        "Demo.Memory": { type: "Transitive", resolved: "4.5.4" },
        "Demo.Http": { type: "CentralTransitive", requested: "[6.0.0, )", resolved: "6.0.0", dependencies: { "Demo.Memory": "4.5.4" } },
        "Demo.Core": { type: "Project", dependencies: { "Demo.Http": "[6.0.0, )" } },
      },
      "net6.0": {
        "Demo.Json": { type: "Direct", requested: "[13.0.1, )", resolved: "13.0.1", dependencies: { "demo.memory": "4.5.4" } },
        "Demo.Memory": { type: "Transitive", resolved: "4.5.4" },
      },
    },
  });
  it("merges frameworks; Direct vs Transitive; project references walked", () => {
    const { packages } = parseNugetPackagesLock(lock);
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["Demo.Http@6.0.0", "Demo.Json@13.0.1", "Demo.Memory@4.5.4"]);
    expect(byName(packages, "Demo.Json").direct).toBe(true);
    expect(byName(packages, "Demo.Memory")).toMatchObject({ direct: false, introducedVia: ["Demo.Json@13.0.1"] });
    expect(byName(packages, "Demo.Http").direct).toBe(false);
    expect(() => parseNugetPackagesLock("{}")).toThrow(LockfileParseError);
  });
});

describe("parseGradleLockfile", () => {
  const lock = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.example:demo-lib:31.1-jre=compileClasspath,runtimeClasspath
org.example:test-kit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.example:annotations:1.0=annotationProcessor
empty=
`;
  it("reads group:artifact:version and scope from configurations", () => {
    const { packages } = parseGradleLockfile(lock);
    expect(packages).toEqual([
      { ecosystem: "Maven", name: "org.example:annotations", version: "1.0", direct: null, dev: true },
      { ecosystem: "Maven", name: "org.example:demo-lib", version: "31.1-jre", direct: null, dev: false },
      { ecosystem: "Maven", name: "org.example:test-kit", version: "4.13.2", direct: null, dev: true },
    ]);
  });
});

describe("parseLockfile", () => {
  it("dispatches by file name and rejects unknown files", () => {
    expect(parseLockfile("Cargo.lock", `[[package]]\nname = "x"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`).packages).toHaveLength(1);
    expect(() => parseLockfile("random.lock", "")).toThrow(LockfileParseError);
    expect(LOCKFILES.map((l) => l.file)).toContain("pnpm-lock.yaml");
  });
});
