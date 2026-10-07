#!/usr/bin/env bash
#
# burp_export.sh - SAINT's Burp Suite Community import helper
#
# Burp Community's scanner isn't automatable the way ZAP is, so this isn't a
# launcher -- it's an importer. Workflow:
#
#   1. In Burp (Community or Pro), manually crawl/test your AUTHORIZED target.
#   2. Export your findings: Burp > Target > Issues > right-click > "Report
#      selected issues" -> XML. (Community edition can still export issues
#      you've manually recorded/annotated, even without the automated scanner.)
#   3. Save that export somewhere, then run this script to copy it into
#      SAINT's output tree and normalize it.
#
# Usage:
#   ./burp_export.sh --target-name example-lab-app --input /path/to/burp_export.xml

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/output/burp"

TARGET_NAME=""
INPUT_FILE=""

usage() {
  echo "Usage: $0 --target-name <name> --input <path to Burp XML export>"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-name)
      TARGET_NAME="$2"; shift 2 ;;
    --input)
      INPUT_FILE="$2"; shift 2 ;;
    -h|--help)
      usage ;;
    *)
      echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "${TARGET_NAME}" || -z "${INPUT_FILE}" ]]; then
  echo "ERROR: --target-name and --input are both required."
  usage
fi

if [[ ! -f "${INPUT_FILE}" ]]; then
  echo "ERROR: Input file not found: ${INPUT_FILE}"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
RAW_COPY="${OUTPUT_DIR}/${TARGET_NAME}_burp_raw.xml"
JSON_OUT="${OUTPUT_DIR}/${TARGET_NAME}_burp_findings.json"

cp "${INPUT_FILE}" "${RAW_COPY}"
echo "Copied raw export to ${RAW_COPY}"

python3 "${SCRIPT_DIR}/../parse_and_aggregate/normalize_burp.py" \
  --xml "${RAW_COPY}" \
  --target-name "${TARGET_NAME}" \
  --out "${JSON_OUT}"

echo "Wrote: ${JSON_OUT}"
