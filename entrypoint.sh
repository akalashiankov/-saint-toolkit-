#!/bin/bash
echo "[*] Starting OWASP ZAP daemon in background..."
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=letshego-zap-2026 -config api.disablekey=true &

# Give ZAP a moment to initialize its process
sleep 5

if [ $# -gt 0 ]; then
    exec "$@"
else
    tail -f /dev/null
fi
