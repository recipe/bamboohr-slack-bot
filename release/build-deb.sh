#!/usr/bin/env bash
# Builds the Debian package in bin/. It runs inside a golang Docker image (see `make deb`),
# so neither Go nor dpkg is needed on the host.
#
# Usage: release/build-deb.sh <version> <arch>, e.g. release/build-deb.sh 1.1.0 amd64

set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?architecture is required}"
BOT=bamboohr-slack-bot
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$SRC"
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$WORK/$BOT" "./cmd/$BOT"

PKG="$WORK/${BOT}_${VERSION}-1"
cp -R "release/debian/$BOT" "$PKG"
# Files left by macOS Finder in the source tree must not be installed.
find "$PKG" \( -name .DS_Store -o -name '._*' \) -delete
mkdir -p "$PKG/opt/$BOT/bin" "$PKG/etc/$BOT" "$PKG/usr/share/doc/$BOT"
cp "$WORK/$BOT" "$PKG/opt/$BOT/bin/"
cp config.yml-sample "$PKG/etc/$BOT/"
cp third_party/satisfy/LICENSE.txt "$PKG/usr/share/doc/$BOT/LICENSE-satisfy.txt"
sed -i "s/Version:.*/Version: $VERSION/; s/Architecture:.*/Architecture: $ARCH/" "$PKG/DEBIAN/control"
chmod 0755 "$PKG/opt/$BOT/bin/$BOT" "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"

# Installed files must be owned by root, not by the user who built the package.
mkdir -p bin
dpkg-deb --root-owner-group --build "$PKG" "bin/${BOT}_${VERSION}-1_${ARCH}.deb"
# Give the package to the owner of the source tree, not to root of the container.
chown "$(stat -c %u:%g "$SRC")" "bin/${BOT}_${VERSION}-1_${ARCH}.deb"
