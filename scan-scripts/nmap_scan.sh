#!/usr/bin/env bash
#
# nmap_scan.sh - SAINT's Nmap recon module
#
# Scans ONLY targets listed in config/targets.yaml. There is no raw-hostname
# passthrough mode: you must add the target to targets.yaml first, which is
# also your authorization record for the scan.
#
# Usage:
#   ./nmap_scan.sh --target-name example-lab-app
#
# Output:
#   output/nmap/<target-name>_scan.xml
#   output/nmap/<target-name>_scan.json   (normalized)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGETS_FILE="${ROOT_DIR}/config/targets.yaml"
OUTPUT_DIR="${ROOT_DIR}/output/nmap"

TARGET_NAME=""

usage() {
  echo "Usage: $0 --target-name <name from config/targets.yaml>"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-name)
      TARGET_NAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      ;;
  esac
done

if [[ -z "${TARGET_NAME}" ]]; then
  echo "ERROR: --target-name is required."
  usage
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "ERROR: nmap is not installed or not on PATH."
  exit 1
fi

if ! command -v yq >/dev/null 2>&1; then
  echo "ERROR: 'yq' is required to parse config/targets.yaml (https://github.com/mikefarah/yq)."
  exit 1
fi

if [[ ! -f "${TARGETS_FILE}" ]]; then
  echo "ERROR: Targets file not found at ${TARGETS_FILE}"
  exit 1
fi

# --- Look up the target entry by name -------------------------------------
TARGET_COUNT=$(yq ".targets[] | select(.name == \"${TARGET_NAME}\") | .name" "${TARGETS_FILE}" | wc -l | tr -d ' ')

if [[ "${TARGET_COUNT}" -eq 0 ]]; then
  echo "ERROR: No target named '${TARGET_NAME}' found in ${TARGETS_FILE}."
  echo "Add it there first -- that file is SAINT's authorization record. Refusing to scan unlisted targets."
  exit 1
fi

HOST=$(yq -r ".targets[] | select(.name == \"${TARGET_NAME}\") | .host" "${TARGETS_FILE}")
PROFILE=$(yq -r ".targets[] | select(.name == \"${TARGET_NAME}\") | .profile" "${TARGETS_FILE}")
AUTH_REF=$(yq -r ".targets[] | select(.name == \"${TARGET_NAME}\") | .authorization_ref" "${TARGETS_FILE}")
REQUIRE_AUTH_REF=$(yq -r ".defaults.require_authorization_ref" "${TARGETS_FILE}")

echo "Target:       ${TARGET_NAME} (${HOST})"
echo "Profile:      ${PROFILE}"
echo "Auth ref:     ${AUTH_REF}"

# --- Refuse a full scan on a placeholder authorization ----------------------
if [[ "${PROFILE}" == "full" && "${REQUIRE_AUTH_REF}" == "true" ]]; then
  if [[ "${AUTH_REF}" == CHANGE_ME* || -z "${AUTH_REF}" ]]; then
    echo "ERROR: Profile is 'full' but authorization_ref in targets.yaml is still a placeholder."
    echo "Fill in a real authorization reference before running a full scan."
    exit 1
  fi
fi

# --- Select nmap arguments by profile ---------------------------------------
if [[ "${PROFILE}" == "full" ]]; then
  NMAP_ARGS=$(yq -r ".defaults.nmap.full_args" "${TARGETS_FILE}")
elif [[ "${PROFILE}" == "light" ]]; then
  NMAP_ARGS=$(yq -r ".defaults.nmap.light_args" "${TARGETS_FILE}")
else
  echo "ERROR: Unknown profile '${PROFILE}' for target '${TARGET_NAME}'. Expected 'light' or 'full'."
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
XML_OUT="${OUTPUT_DIR}/${TARGET_NAME}_scan.xml"
JSON_OUT="${OUTPUT_DIR}/${TARGET_NAME}_scan.json"

echo ""
echo "Running: nmap ${NMAP_ARGS} -oX ${XML_OUT} ${HOST}"
echo ""

# shellcheck disable=SC2086
nmap ${NMAP_ARGS} -oX "${XML_OUT}" "${HOST}"

echo ""
echo "Nmap scan complete. Normalizing XML -> JSON..."

python3 "${SCRIPT_DIR}/../parse_and_aggregate/normalize_nmap.py" \
  --xml "${XML_OUT}" \
  --target-name "${TARGET_NAME}" \
  --out "${JSON_OUT}"

echo "Wrote:"
echo "  ${XML_OUT}"
echo "  ${JSON_OUT}"
