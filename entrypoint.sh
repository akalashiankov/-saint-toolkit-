#!/bin/bash
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true > /dev/null 2>&1 &
exec python3 -u ui.py
