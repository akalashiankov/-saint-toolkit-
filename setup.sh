#!/bin/bash
echo "[*] Setting up SAINT..."

if ! command -v nmap &> /dev/null; then
    echo "[+] Installing Nmap..."
    sudo apt update && sudo apt install nmap -y
else
    echo "[*] Nmap is already installed."
fi

if ! command -v yq &> /dev/null; then
    echo "[+] Installing yq..."
    sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq && sudo chmod +x /usr/local/bin/yq
else
    echo "[*] yq is already installed."
fi

echo "[+] Installing Python requirements..."
pip install -r requirements.txt --break-system-packages

mkdir -p output/nmap output/zap output/burp output/manual_poc output/final_report config
echo "[*] Setup complete!"
