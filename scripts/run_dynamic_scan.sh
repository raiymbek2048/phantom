#!/bin/bash
# Dynamic mobile scan — runs on the server
ADB=/mnt/docker/android-sdk/platform-tools/adb
TOOLS=/mnt/docker/phantom-tools/bin

# Kill old processes
pkill -f mitmdump 2>/dev/null
pkill -f 'frida ' 2>/dev/null
sleep 2

# Clear capture
echo '[]' > /tmp/phantom_mitm_capture.json

# Start mitmproxy
nohup $TOOLS/mitmdump -p 8888 -s /tmp/phantom_mitm_addon.py --set ssl_insecure=true > /tmp/mitmproxy.log 2>&1 &
sleep 2
echo 'mitmproxy started'

# Set proxy on emulator
$ADB shell settings put global http_proxy 10.0.2.2:8888
echo 'proxy set'

# Restart frida-server
$ADB shell 'pkill frida-server; sleep 1; /data/local/tmp/frida-server -D &'
sleep 3
echo 'frida-server started'

# Launch app
PKG=${1:-kz.kkb.homebank}
$ADB shell am force-stop $PKG
sleep 1
$ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>/dev/null
echo "app $PKG launched, waiting 20s..."
sleep 20

# Check results
echo '=== CAPTURED TRAFFIC ==='
python3 /tmp/check_capture.py

echo '=== MITMPROXY ERRORS ==='
grep -c 'TLS handshake failed' /tmp/mitmproxy.log || true
grep 'homebank\|halyk' /tmp/mitmproxy.log | tail -5
