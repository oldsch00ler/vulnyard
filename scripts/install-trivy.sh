#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
#
# Downloads a pinned Trivy release, verifies its SHA256 checksum and installs
# the binary into the target directory (default ./.bin).
#
# Usage: bash scripts/install-trivy.sh [target-dir]
#
# Upgrading Trivy: bump TRIVY_VERSION and replace both checksums below with the
# values from https://github.com/aquasecurity/trivy/releases (file
# trivy_<version>_checksums.txt).
#
# The version is tied to Dependency-Track, not just to Trivy. Verified against
# real instances:
#   * Trivy 0.70.0 emits CycloneDX 1.6, accepted by Dependency-Track 4.13 and 4.14
#   * Trivy 0.71.0+ emits CycloneDX 1.7, rejected by 4.13 ("Unrecognized
#     specVersion 1.7"), accepted by 4.14.4
# 0.70.0 is therefore the default: it works with every supported Dependency-Track
# (4.12 and newer). If every instance you upload to runs 4.14 or newer, you can
# bump to the latest Trivy; a wrong combination fails on upload with a message
# saying exactly that.

set -euo pipefail

TRIVY_VERSION="0.70.0"

# SHA256 of the release archives, taken from trivy_<version>_checksums.txt.
SHA256_LINUX_64BIT="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
SHA256_LINUX_ARM64="2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d"

TARGET_DIR="${1:-./.bin}"
BASE_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"

die() {
  echo "install-trivy: ERROR: $*" >&2
  exit 1
}

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is required but not installed."
done

# Platform-specific archive and its expected checksum.
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64)
    archive="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    expected_sha="$SHA256_LINUX_64BIT"
    ;;
  aarch64 | arm64)
    archive="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"
    expected_sha="$SHA256_LINUX_ARM64"
    ;;
  *)
    die "unsupported architecture '$arch' (supported: x86_64, aarch64)."
    ;;
esac

# sha256sum on Linux, shasum on macOS.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "neither 'sha256sum' nor 'shasum' is available."
  fi
}

work_dir="$(mktemp -d)"
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

echo "install-trivy: downloading Trivy ${TRIVY_VERSION} (${archive})"
curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  --output "$work_dir/$archive" "$BASE_URL/$archive" ||
  die "download of $archive failed ($BASE_URL/$archive)."

checksums="trivy_${TRIVY_VERSION}_checksums.txt"
curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  --output "$work_dir/$checksums" "$BASE_URL/$checksums" ||
  die "download of $checksums failed ($BASE_URL/$checksums)."

# The checksum published with the release must match the one pinned here; a
# mismatch means the pinned value is stale or the download was tampered with.
published_sha="$(awk -v name="$archive" '$2 == name || $2 == "*" name {print $1}' "$work_dir/$checksums")"
[ -n "$published_sha" ] || die "no checksum for $archive in $checksums."
[ "$published_sha" = "$expected_sha" ] ||
  die "checksum pinned in this script does not match the published one for $archive (pinned $expected_sha, published $published_sha)."

actual_sha="$(sha256_of "$work_dir/$archive")"
[ "$actual_sha" = "$expected_sha" ] ||
  die "SHA256 mismatch for $archive (expected $expected_sha, got $actual_sha)."
echo "install-trivy: SHA256 verified ($actual_sha)"

mkdir -p "$TARGET_DIR"
tar -xzf "$work_dir/$archive" -C "$work_dir" trivy ||
  die "could not extract the 'trivy' binary from $archive."
install -m 0755 "$work_dir/trivy" "$TARGET_DIR/trivy" 2>/dev/null ||
  { cp "$work_dir/trivy" "$TARGET_DIR/trivy" && chmod 0755 "$TARGET_DIR/trivy"; } ||
  die "could not install the binary into $TARGET_DIR."

echo "install-trivy: installed into $TARGET_DIR/trivy"
"$TARGET_DIR/trivy" --version || die "the installed binary is not runnable."
