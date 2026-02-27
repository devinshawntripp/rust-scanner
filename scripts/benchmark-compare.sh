#!/usr/bin/env bash
set -euo pipefail

# Benchmark helper for comparison content.
# Runs ScanRook, Trivy, and Grype against the same local artifact and writes
# a machine-readable CSV + JSON outputs.

ARTIFACT_PATH="${1:-}"
OUT_DIR="${2:-./benchmark-out}"
SCANROOK_BIN="${SCANROOK_BIN:-scanrook}"

if [[ -z "${ARTIFACT_PATH}" ]]; then
  echo "Usage: $0 <artifact.tar|iso|bin> [out_dir]" >&2
  exit 1
fi
if [[ ! -f "${ARTIFACT_PATH}" ]]; then
  echo "Artifact not found: ${ARTIFACT_PATH}" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

need_cmd "${SCANROOK_BIN}"
need_cmd jq
need_cmd trivy
need_cmd grype

mkdir -p "${OUT_DIR}"
CSV="${OUT_DIR}/summary.csv"
echo "tool,duration_seconds,findings_count,output_path" > "${CSV}"

run_and_record() {
  local tool="$1"
  local outfile="$2"
  shift 2

  local start end elapsed findings
  start="$(date +%s)"
  "$@" >/dev/null
  end="$(date +%s)"
  elapsed="$((end - start))"

  case "${tool}" in
    scanrook)
      findings="$(jq -r '.summary.total_findings // (.findings | length) // 0' "${outfile}" 2>/dev/null || echo 0)"
      ;;
    trivy)
      findings="$(jq -r '[.Results[]?.Vulnerabilities[]?] | length' "${outfile}" 2>/dev/null || echo 0)"
      ;;
    grype)
      findings="$(jq -r '.matches | length // 0' "${outfile}" 2>/dev/null || echo 0)"
      ;;
    *)
      findings=0
      ;;
  esac

  echo "${tool},${elapsed},${findings},${outfile}" >> "${CSV}"
}

SCANROOK_JSON="${OUT_DIR}/scanrook.json"
TRIVY_JSON="${OUT_DIR}/trivy.json"
GRYPE_JSON="${OUT_DIR}/grype.json"

echo "Running ScanRook..."
run_and_record scanrook "${SCANROOK_JSON}" \
  "${SCANROOK_BIN}" scan --file "${ARTIFACT_PATH}" --mode deep --format json --out "${SCANROOK_JSON}"

echo "Running Trivy..."
run_and_record trivy "${TRIVY_JSON}" \
  trivy image --input "${ARTIFACT_PATH}" --format json --output "${TRIVY_JSON}"

echo "Running Grype..."
run_and_record grype "${GRYPE_JSON}" \
  sh -c "grype '${ARTIFACT_PATH}' -o json > '${GRYPE_JSON}'"

echo "Done."
echo "Summary: ${CSV}"
echo "Raw outputs: ${OUT_DIR}"
