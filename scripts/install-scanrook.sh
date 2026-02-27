#!/usr/bin/env bash
set -euo pipefail

# Minimal install helper for ScanRook CLI release artifacts.
# Expected artifact pattern:
#   scanrook-${VERSION}-${OS}-${ARCH}.tar.gz
#   scanrook-${VERSION}-checksums.txt

VERSION="${SCANROOK_VERSION:-latest}"
REPO="${SCANROOK_REPO:-devintripp/rust_scanner}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

if [[ "${VERSION}" == "latest" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | jq -r '.tag_name')"
  VERSION="${VERSION#v}"
fi

ASSET="scanrook-${VERSION}-${OS}-${ARCH}.tar.gz"
SUMS="scanrook-${VERSION}-checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading ${ASSET} ..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP}/${ASSET}"
curl -fsSL "${BASE_URL}/${SUMS}" -o "${TMP}/${SUMS}"

echo "Verifying checksum ..."
(cd "${TMP}" && grep " ${ASSET}$" "${SUMS}" | sha256sum -c -)

echo "Installing to ${INSTALL_DIR} ..."
tar -xzf "${TMP}/${ASSET}" -C "${TMP}"
install -m 0755 "${TMP}/scanrook" "${INSTALL_DIR}/scanrook"

# Back-compat alias for existing environments.
ln -sf "${INSTALL_DIR}/scanrook" "${INSTALL_DIR}/scanner"

echo "Installed scanrook ${VERSION} to ${INSTALL_DIR}"
