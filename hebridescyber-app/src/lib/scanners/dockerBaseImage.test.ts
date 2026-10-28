import { describe, it, expect } from "vitest";
import {
  parseTopLevelArgs,
  parseDockerfileStages,
  resolveBaseImages,
  parseImageRef,
  officialFamilyName,
} from "./dockerBaseImage";

// Pure Dockerfile-parsing helpers (no network, no binary). These back the
// base-image EOL check; before this they had zero coverage despite the fiddly
// edge cases (registry-port vs tag colon, ARG substitution, multi-stage alias
// chains, Docker Hub official-image namespace rules).

describe("parseTopLevelArgs", () => {
  it("reads ARG defaults and strips quotes", () => {
    const args = parseTopLevelArgs(`ARG NODE_VERSION=20\nARG TAG="3.19"\nARG X='bar'`);
    expect(args.get("NODE_VERSION")).toBe("20");
    expect(args.get("TAG")).toBe("3.19");
    expect(args.get("X")).toBe("bar");
  });
  it("ignores an ARG with no default", () => {
    expect(parseTopLevelArgs(`ARG NO_DEFAULT`).has("NO_DEFAULT")).toBe(false);
  });
});

describe("parseDockerfileStages", () => {
  it("parses FROM lines, aliases, and skips comments/other instructions", () => {
    const df = `# comment\nFROM node:20 AS build\nRUN npm ci\nFROM nginx:1.27`;
    expect(parseDockerfileStages(df)).toEqual([
      { imageRef: "node:20", alias: "build" },
      { imageRef: "nginx:1.27", alias: null },
    ]);
  });
  it("substitutes ARG defaults into the image ref (both ${...} and $NAME forms)", () => {
    const df = `ARG NODE_VERSION=20\nFROM node:\${NODE_VERSION}-slim\nFROM alpine:$NODE_VERSION`;
    const stages = parseDockerfileStages(df);
    expect(stages[0].imageRef).toBe("node:20-slim");
    expect(stages[1].imageRef).toBe("alpine:20");
  });
  it("honours --platform and leaves an unknown ARG untouched", () => {
    const stages = parseDockerfileStages(`FROM --platform=linux/amd64 node:\${UNKNOWN} AS b`);
    expect(stages[0]).toEqual({ imageRef: "node:${UNKNOWN}", alias: "b" });
  });
});

describe("resolveBaseImages", () => {
  it("follows a stage-alias chain to the real external image and flags only the final stage", () => {
    const stages = parseDockerfileStages(
      `FROM node:20 AS deps\nFROM deps AS build\nFROM build`,
    );
    const images = resolveBaseImages(stages);
    // All three stages resolve to the one external image node:20; deduped.
    expect(images).toEqual([{ imageRef: "node:20", isFinalStage: true }]);
  });
  it("keeps distinct external images and marks what the last stage ships", () => {
    const stages = parseDockerfileStages(`FROM golang:1.23 AS build\nFROM gcr.io/distroless/base`);
    const images = resolveBaseImages(stages);
    expect(images).toEqual([
      { imageRef: "golang:1.23", isFinalStage: false },
      { imageRef: "gcr.io/distroless/base", isFinalStage: true },
    ]);
  });
  it("returns nothing for no stages", () => {
    expect(resolveBaseImages([])).toEqual([]);
  });
});

describe("parseImageRef", () => {
  it("splits repo and tag", () => {
    expect(parseImageRef("node:20")).toEqual({ repoPath: "node", tag: "20", digestPinned: false });
  });
  it("does not mistake a registry port for a tag", () => {
    expect(parseImageRef("localhost:5000/node:18")).toEqual({
      repoPath: "localhost:5000/node",
      tag: "18",
      digestPinned: false,
    });
  });
  it("detects a digest pin and drops the digest", () => {
    const r = parseImageRef("node:20@sha256:abc123");
    expect(r.digestPinned).toBe(true);
    expect(r.repoPath).toBe("node");
    expect(r.tag).toBe("20");
  });
  it("handles a bare repo with no tag", () => {
    expect(parseImageRef("ubuntu")).toEqual({ repoPath: "ubuntu", tag: null, digestPinned: false });
  });
});

describe("officialFamilyName", () => {
  it("returns the bare name for a Docker Hub official image", () => {
    expect(officialFamilyName("node")).toBe("node");
    expect(officialFamilyName("docker.io/library/node")).toBe("node");
    expect(officialFamilyName("library/nginx")).toBe("nginx");
  });
  it("returns null for namespaced, registry-hosted, empty or ARG-templated refs", () => {
    expect(officialFamilyName("bitnami/node")).toBeNull();
    expect(officialFamilyName("ghcr.io/foo/node")).toBeNull();
    expect(officialFamilyName("myorg/node")).toBeNull();
    expect(officialFamilyName("")).toBeNull();
    expect(officialFamilyName("$BASE")).toBeNull();
  });
});
