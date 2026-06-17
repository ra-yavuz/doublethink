#!/usr/bin/env bash
# Build a doublethink .deb without debhelper, for environments where the full
# Debian build tooling is not available. Produces an arch-specific binary package
# under dist/. Mirrors the no-debhelper template used across the ra-yavuz repos,
# adapted for a compiled Go binary.
#
# Run inside the dev container (it has the Go toolchain):
#   .claude-dev/run.sh bash scripts/build-deb.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -nE '1 s/^[^(]*\(([^)]+)\).*/\1/p' "$ROOT/debian/changelog")
[ -n "$VERSION" ] || { echo "could not parse version from debian/changelog" >&2; exit 1; }

# Debian architecture of the build host (amd64, arm64, ...).
ARCH=$(dpkg --print-architecture 2>/dev/null || go env GOARCH)

PKG_DIR="$ROOT/dist/doublethink_${VERSION}_${ARCH}"
DEB_OUT="$ROOT/dist/doublethink_${VERSION}_${ARCH}.deb"

rm -rf "$PKG_DIR" "$DEB_OUT"
mkdir -p "$PKG_DIR/DEBIAN" \
         "$PKG_DIR/usr/bin" \
         "$PKG_DIR/lib/systemd/system" \
         "$PKG_DIR/usr/share/doc/doublethink"

echo "building doublethink binary (version $VERSION, arch $ARCH)..."
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags=-s -o "$PKG_DIR/usr/bin/doublethink" ./cmd/doublethink )
chmod 0755 "$PKG_DIR/usr/bin/doublethink"

install -m 0644 "$ROOT/systemd/doublethink.service" "$PKG_DIR/lib/systemd/system/doublethink.service"
install -m 0644 "$ROOT/README.md"                   "$PKG_DIR/usr/share/doc/doublethink/README.md"
install -m 0644 "$ROOT/LICENSE"                      "$PKG_DIR/usr/share/doc/doublethink/copyright"
install -m 0755 "$ROOT/debian/postinst"             "$PKG_DIR/DEBIAN/postinst"
install -m 0755 "$ROOT/debian/postrm"               "$PKG_DIR/DEBIAN/postrm"

# DEBHELPER tokens are only meaningful under dh; strip them for the portable build.
sed -i '/#DEBHELPER#/d' "$PKG_DIR/DEBIAN/postinst" "$PKG_DIR/DEBIAN/postrm"

INSTALLED_KB=$(du -ks "$PKG_DIR" | cut -f1)

cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: doublethink
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Ramazan Yavuz <yavuzramazan1994@gmail.com>
Installed-Size: ${INSTALLED_KB}
Homepage: https://github.com/ra-yavuz/doublethink
Description: secure pub/sub broker, ntfy-easy with genuinely private channels
 doublethink is a publish/subscribe message broker that is as easy to stand up as
 ntfy, but with real authentication and genuinely private channels. Private
 channels admit only authenticated, authorised parties (Ed25519 challenge/response)
 and their payloads are end-to-end encrypted so the broker never sees plaintext.
 Pairing is man-in-the-middle resistant. Opt-in plaintext public topics work
 ntfy-style. Delivery is bidirectional, asynchronous, and streaming.
 .
 DISCLAIMER: doublethink carries other parties' private traffic and enforces
 access to it. It is provided AS IS, WITHOUT WARRANTY OF ANY KIND. You alone are
 responsible for how you deploy and secure it and for the data that flows through
 it. The author is not liable for any harm, however caused.
EOF

echo "packing $DEB_OUT ..."
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_OUT" >/dev/null
echo "built: $DEB_OUT"
dpkg-deb --info "$DEB_OUT" | sed -n '1,12p'
