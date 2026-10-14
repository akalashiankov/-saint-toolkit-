#!/bin/bash

# Colors for Metasploit-style UI
RED='\033[1;31m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RESET='\033[0m'

clear
echo -e "${RED}  ____   _    ___ _   _ _____ ${RESET}"
echo -e "${RED} / ___| / \  |_ _| \ | |_   _|${RESET}"
echo -e "${CYAN}| (___ / _ \  | ||  \| | | |  ${RESET}"
echo -e "${CYAN} \___ \/ ___ \ | || |\  | | |  ${RESET}"
echo -e "${BLUE}  ____) /   \_\___|_| \_| |_|  ${RESET}"
echo "=================================================="
echo "         SAINT SECURITY TOOLKIT - SETUP           "
echo "=================================================="
echo ""

read -p "Enter Target Name (e.g., Target Name UAT): " TARGET_NAME
read -p "Enter Target Base URL (e.g., https://api.uat.example.com): " TARGET_URL
read -p "Enter Assessment Type [webapp/api]: " ASSESS_TYPE
ASSESS_TYPE=${ASSESS_TYPE:-webapp}

OPENAPI_URL=""
if [ "$ASSESS_TYPE" = "api" ]; then
    read -p "Enter OpenAPI/Swagger JSON/YAML URL or Path (optional, press enter to skip): " OPENAPI_URL
fi

read -p "Enter Authorized By (e.g., Client Security Team): " AUTH_BY
read -p "Enter Authorization Reference (e.g., SOW-REF-2026-001): " AUTH_REF

# Ensure config directory exists
mkdir -p config

# Write to config/targets.yaml
cat << EOT > config/targets.yaml
targets:
  - name: "${TARGET_NAME}"
    base_url: "${TARGET_URL}"
    type: "${ASSESS_TYPE}"
    openapi_spec: "${OPENAPI_URL}"
    authorized_by: "${AUTH_BY:-Authorized Client}"
    authorization_ref: "${AUTH_REF:-SOW-REF-2026-001}"
EOT

echo ""
echo "[+] Target configuration successfully saved to config/targets.yaml!"
echo "[*] Launching SAINT Security Assessment Appliance..."
echo ""

# Use explicit absolute path for docker-compose
/usr/local/bin/docker-compose build
/usr/local/bin/docker-compose run --rm security-scanner python3 run_scan.py --target-name "${TARGET_NAME}"

echo "[*] Assessment complete. Check the reports/ directory for your PDF report."
