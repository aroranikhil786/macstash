#!/usr/bin/env bash
# Build release binaries and publish SHA-256 checksums for every artifact (R12).
#
# Checksums are the whole supply-chain story for a tool like this until there is
# a signing certificate: they let someone verify that the binary they downloaded
# is the binary that was built. The Homebrew formula path does not receive the
# quarantine attribute, so Gatekeeper is not a blocker there; notarisation
# matters only for direct downloads, and can wait until a Developer account is
# justified.
set -euo pipefail

VERSION="${1:?usage: release.sh <version>}"
OUT="dist/$VERSION"
mkdir -p "$OUT"

for target in "darwin/arm64" "darwin/amd64"; do
  GOOS="${target%/*}" GOARCH="${target#*/}"
  name="macstash-$VERSION-$GOOS-$GOARCH"
  echo "building $name"
  GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
    -o "$OUT/$name" ./cmd/macstash
  (cd "$OUT" && tar czf "$name.tar.gz" "$name" && rm "$name")
done

(cd "$OUT" && shasum -a 256 ./*.tar.gz > SHA256SUMS)
echo
echo "Artifacts in $OUT:"
cat "$OUT/SHA256SUMS"
echo
echo "Publish SHA256SUMS alongside the release. Verify with:"
echo "  shasum -a 256 -c SHA256SUMS"
