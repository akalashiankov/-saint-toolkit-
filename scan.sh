#!/usr/bin/env bash
#
# scan.sh - SAINT master launcher
#
# Runs Nmap + ZAP against a target already listed in config/targets.yaml,
# then aggregates results (plus any Burp import / manual PoC files already
# present) into the final report.
#
# This script does NOT run Burp or Metasploit -- those stay manual steps
# (see scan-scripts/burp_export.sh and output/manual_poc/). Run those first
# if you want their findings included, then run this.
#
# Usage:
#   ./scan.sh --target-name example-lab-app
#   ./scan.sh --target-name example-lab-app --skip-zap
#   ./scan.sh --target-name example-lab-app --skip-nmap

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_NAME=""
SKIP_NMAP=false
SKIP_ZAP=false

usage() {
  echo "Usage: $0 --target-name <name> [--skip-nmap] [--skip-zap]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-name)
      TARGET_NAME="$2"; shift 2 ;;
    --skip-nmap)
      SKIP_NMAP=true; shift ;;
    --skip-zap)
      SKIP_ZAP=true; shift ;;
    -h|--help)
      usage ;;
    *)
      echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "${TARGET_NAME}" ]]; then
  echo "ERROR: --target-name is required."
  usage
fi

echo "=========================================="
echo " SAINT - Security Assessment & Integrated"
echo "         Network Toolkit"
echo "=========================================="
echo "Target: ${TARGET_NAME}"
echo ""

if [[ "${SKIP_NMAP}" == false ]]; then
  echo ">>> [1/3] Nmap scan"
  "${SCRIPT_DIR}/scan-scripts/nmap_scan.sh" --target-name "${TARGET_NAME}"
  echo ""
else
  echo ">>> [1/3] Skipping Nmap (--skip-nmap)"
fi

if [[ "${SKIP_ZAP}" == false ]]; then
  echo ">>> [2/3] ZAP scan"
  python3 "${SCRIPT_DIR}/scan-scripts/zap_scan.py" --target-name "${TARGET_NAME}"
  echo ""
else
  echo ">>> [2/3] Skipping ZAP (--skip-zap)"
fi

echo ">>> [3/3] Aggregating results into final report"
python3 "${SCRIPT_DIR}/parse_and_aggregate/aggregator.py" --target-name "${TARGET_NAME}"

echo ""
echo "Done. See output/final_report/${TARGET_NAME}_report.{md,html} and _findings.json"
echo ""
echo "Note: Burp and manual PoC findings are included automatically if you've"
echo "already run burp_export.sh or filled in output/manual_poc/ for this target."
