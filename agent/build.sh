#!/usr/bin/env bash
# Cross-compiles UNSIGNED agent binaries into dist/, with SHA-256 sums.
# Signing and notarisation happen afterwards (see SIGNING.md).
#
#   ./build.sh <version>
set -euo pipefail
cd "$(dirname "$0")"
version="${1:?usage: ./build.sh <version>}"
rm -rf dist && mkdir -p dist
targets="windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64"
for t in $targets; do
  goos="${t%/*}" goarch="${t#*/}"
  ext=""; [ "$goos" = windows ] && ext=".exe"
  out="dist/hebrides-agent-${version}-${goos}-${goarch}${ext}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$out" ./cmd/hebrides-agent
  echo "built $out"
done
(cd dist && sha256sum hebrides-agent-* > SHA256SUMS)
cat dist/SHA256SUMS
