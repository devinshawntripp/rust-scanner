#!/usr/bin/env bash
set -euo pipefail

VERSION="${SCANROOK_VERSION:-latest}"
REPO="${SCANROOK_REPO:-devinshawntripp/rust-scanner}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="${SCANROOK_BIN_NAME:-scanrook}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "${OS}" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: ${OS}. Supported: linux, darwin." >&2
    exit 1
    ;;
esac

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}. Supported: amd64, arm64." >&2
    exit 1
    ;;
esac

TMP="$(mktemp -d)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT

if [[ "${VERSION}" == "latest" ]]; then
  META_URL="https://api.github.com/repos/${REPO}/releases/latest"
  META_FILE="${TMP}/release-meta.json"
  HTTP_CODE="$(curl -sSL -o "${META_FILE}" -w "%{http_code}" "${META_URL}" || true)"
  if [[ "${HTTP_CODE}" != "200" ]]; then
    if [[ "${HTTP_CODE}" == "404" ]]; then
      echo "No published GitHub release found for ${REPO}." >&2
      echo "Create a release (not just a tag) and upload scanrook-<version>-<os>-<arch>.tar.gz assets." >&2
      echo "Or run with SCANROOK_VERSION set to an existing release tag." >&2
    else
      echo "Failed to query latest release metadata for ${REPO} (HTTP ${HTTP_CODE})." >&2
    fi
    exit 1
  fi
  META="$(cat "${META_FILE}")"
  VERSION="$(printf '%s\n' "${META}" | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/p' | head -n1)"
  if [[ -z "${VERSION}" ]]; then
    echo "Unable to parse latest release tag for ${REPO}." >&2
    exit 1
  fi
fi

ASSET="scanrook-${VERSION}-${OS}-${ARCH}.tar.gz"
SUMS="scanrook-${VERSION}-checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

echo "Downloading ${ASSET} ..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP}/${ASSET}" || {
  echo "Release asset not found: ${BASE_URL}/${ASSET}" >&2
  echo "Override with SCANROOK_REPO and/or SCANROOK_VERSION if needed." >&2
  exit 1
}
curl -fsSL "${BASE_URL}/${SUMS}" -o "${TMP}/${SUMS}" || {
  echo "Checksum file not found: ${BASE_URL}/${SUMS}" >&2
  exit 1
}

echo "Verifying checksum ..."
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${TMP}" && grep " ${ASSET}$" "${SUMS}" | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
  EXPECTED="$(cd "${TMP}" && grep " ${ASSET}$" "${SUMS}" | awk '{print $1}')"
  ACTUAL="$(shasum -a 256 "${TMP}/${ASSET}" | awk '{print $1}')"
  if [[ -z "${EXPECTED}" || "${EXPECTED}" != "${ACTUAL}" ]]; then
    echo "Checksum verification failed for ${ASSET}" >&2
    exit 1
  fi
else
  echo "No SHA-256 tool found (need sha256sum or shasum)." >&2
  exit 1
fi

echo "Installing to ${INSTALL_DIR} ..."
tar -xzf "${TMP}/${ASSET}" -C "${TMP}"
if [[ ! -f "${TMP}/${BIN_NAME}" ]]; then
  echo "Archive missing binary: ${BIN_NAME}" >&2
  exit 1
fi

if [[ -w "${INSTALL_DIR}" || "$(id -u)" -eq 0 ]]; then
  install -m 0755 "${TMP}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  ln -sf "${INSTALL_DIR}/${BIN_NAME}" "${INSTALL_DIR}/scanner"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "${TMP}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  sudo ln -sf "${INSTALL_DIR}/${BIN_NAME}" "${INSTALL_DIR}/scanner"
else
  FALLBACK_DIR="${HOME}/.local/bin"
  mkdir -p "${FALLBACK_DIR}"
  install -m 0755 "${TMP}/${BIN_NAME}" "${FALLBACK_DIR}/${BIN_NAME}"
  ln -sf "${FALLBACK_DIR}/${BIN_NAME}" "${FALLBACK_DIR}/scanner"
  echo "Installed to ${FALLBACK_DIR}"
  echo "Add to PATH:"
  echo "  export PATH=\"${FALLBACK_DIR}:$PATH\""
  echo "Run: ${BIN_NAME} --help"
  exit 0
fi

echo "Installed ${BIN_NAME} ${VERSION} to ${INSTALL_DIR}"
echo "Run: ${BIN_NAME} --help"
