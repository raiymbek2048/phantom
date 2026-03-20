"""
Mobile Dynamic Scanner — runs APK in headless Android emulator,
intercepts traffic via mitmproxy, bypasses SSL pinning with Frida.

All commands execute via SSH to the host machine because the backend
runs inside Docker while emulator/adb/frida/mitmproxy live on the host.

Pipeline:
1. Start headless Android emulator (if not running)
2. Install mitmproxy CA cert as system cert (tmpfs overlay)
3. Install APK via adb
4. Start mitmproxy traffic capture
5. Launch app, wait for initialization
6. Attach Frida agent (SSL bypass + proxy injection + Flutter bypass)
7. Auto-interact with UI via monkey/uiautomator
8. Capture all HTTP/S traffic
9. Extract real API endpoints, tokens, headers
10. Feed endpoints to PHANTOM for attack

Requires on server: Android SDK, mitmproxy, frida-tools, frida-server on emulator
"""
import asyncio
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# SSH connection to host (emulator + tools run there, backend is in Docker)
# host.docker.internal resolves to host machine (set via extra_hosts in docker-compose)
SSH_HOST = os.environ.get("DYNAMIC_SCAN_HOST", "host.docker.internal")
SSH_USER = os.environ.get("DYNAMIC_SCAN_USER", "trade")
SSH_KEY = os.environ.get("DYNAMIC_SCAN_KEY", "/app/.ssh/id_ed25519")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]

# Paths on the HOST machine
ANDROID_HOME = "/mnt/docker/android-sdk"
ANDROID_AVD_HOME = "/mnt/docker/android-avd"
ADB = os.path.join(ANDROID_HOME, "platform-tools", "adb")
EMULATOR = os.path.join(ANDROID_HOME, "emulator", "emulator")
AVD_NAME = "phantom_avd"
MITMPROXY_PORT = 8888
FRIDA_PORT = 27042

# Tools path on HOST (venv with mitmproxy + frida)
TOOLS_BIN = "/mnt/docker/phantom-tools/bin"

# ─── Frida SSL Bypass Script (Universal: Java + Flutter + OkHttp proxy injection) ───

SSL_BYPASS_SCRIPT = r"""
'use strict';

// ===== FLUTTER / DART SSL BYPASS (NVISO-based + multi-method) =====
(function() {
    var flutter = Process.findModuleByName("libflutter.so");
    if (!flutter) {
        console.log("[PHANTOM] No libflutter.so — skipping Flutter bypass");
        return;
    }
    console.log("[PHANTOM] Flutter detected (" + flutter.size + " bytes)! Bypassing SSL...");
    var patched = false;

    function patchVerify(addr, label) {
        try {
            Interceptor.replace(addr, new NativeCallback(function() {
                return 0;
            }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
            console.log("[PHANTOM] " + label + " at " + addr);
            patched = true;
        } catch(e) {
            // Try attach+retval instead of replace
            try {
                Interceptor.attach(addr, {
                    onLeave: function(retval) { retval.replace(0x0); }
                });
                console.log("[PHANTOM] " + label + " (attach mode) at " + addr);
                patched = true;
            } catch(e2) {}
        }
    }

    // Method 1: Architecture-specific byte patterns (from NVISO disable-flutter-tls)
    // These target ssl_crypto_x509_session_verify_cert_chain
    var arch_patterns = [
        // x86_64 (Android emulator)
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02",
        // x86_64 variant 2
        "55 41 57 41 56 41 55 41 54 53 48 83 EC ?? C6 02",
        // ARM64/ARMv8
        "FF 03 05 D1 FC 6B 0F A9 F9 63 10 A9 F7 5B 11 A9 F5 53 12 A9 F3 7B 13 A9 08 0A 80 52",
        // ARM64 variant (NVISO)
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? 5? 02 A9",
        // ARM32/ARMv7
        "2D E9 F0 4F A3 B0 81 46 50 20 10 70",
    ];
    arch_patterns.forEach(function(pat) {
        if (patched) return;
        try {
            var matches = Memory.scanSync(flutter.base, flutter.size, pat);
            if (matches.length === 1) {
                patchVerify(matches[0].address, "Pattern match (unique)");
            } else if (matches.length > 1) {
                console.log("[PHANTOM] Pattern matched " + matches.length + " times, trying first");
                patchVerify(matches[0].address, "Pattern match (first of " + matches.length + ")");
            }
        } catch(e) {}
    });

    // Method 2: Known export names (older Flutter versions expose symbols)
    if (!patched) {
        var exports_to_hook = [
            "ssl_crypto_x509_session_verify_cert_chain",
            "SSL_CTX_set_verify", "X509_verify_cert", "ssl_verify_peer_cert",
        ];
        exports_to_hook.forEach(function(name) {
            if (patched) return;
            try {
                var addr = Module.findExportByName("libflutter.so", name);
                if (addr) patchVerify(addr, "Export hook: " + name);
            } catch(e) {}
        });
    }

    // Method 3: Enumerate all exports for ssl/x509 related symbols
    if (!patched) {
        try {
            flutter.enumerateExports().forEach(function(sym) {
                if (patched) return;
                var n = sym.name.toLowerCase();
                if (n.indexOf("ssl_verify") !== -1 || n.indexOf("x509_verify") !== -1 ||
                    n.indexOf("verify_cert_chain") !== -1 || n.indexOf("ssl_set_verify") !== -1) {
                    patchVerify(sym.address, "Symbol: " + sym.name);
                }
            });
        } catch(e) {}
    }

    if (!patched) {
        console.log("[PHANTOM] WARNING: Flutter SSL bypass failed — no matching pattern/export found");
    }
})();

// ===== JAVA SSL BYPASS =====
setTimeout(function() {
    Java.perform(function() {
        console.log("[PHANTOM] Java SSL bypass starting...");

        // 1. TrustManagerImpl.verifyChain — Android 14 signature
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.overload(
                'java.util.List', 'java.util.List',
                'java.lang.String', 'boolean', '[B', '[B'
            ).implementation = function(sigAlgs, untrustedChain, authType, srv, ocsp, tls) {
                console.log("[PHANTOM] verifyChain BYPASSED");
                return untrustedChain;
            };
            console.log("[PHANTOM] verifyChain hooked OK");
        } catch(e) {
            // Fallback: older Android versions
            try {
                var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TMI.verifyChain.overload(
                    '[Ljava.security.cert.X509Certificate;',
                    'java.lang.String', 'java.lang.String',
                    'java.lang.String', 'java.lang.String',
                    'boolean', '[B'
                ).implementation = function(untrustedChain) {
                    console.log("[PHANTOM] verifyChain(old) BYPASSED");
                    return untrustedChain;
                };
                console.log("[PHANTOM] verifyChain(old) hooked OK");
            } catch(e2) {}
        }

        // 1b. TrustManagerImpl.checkTrusted — both Android 14 overloads
        try {
            Java.use('com.android.org.conscrypt.TrustManagerImpl').checkTrusted.overload(
                '[Ljava.security.cert.X509Certificate;', 'java.lang.String',
                'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean'
            ).implementation = function(chain, auth, sess, params, srv) {
                console.log("[PHANTOM] checkTrusted BYPASSED");
                return Java.use('java.util.Arrays').asList(chain);
            };
            console.log("[PHANTOM] checkTrusted(session) hooked OK");
        } catch(e) {}
        try {
            Java.use('com.android.org.conscrypt.TrustManagerImpl').checkTrusted.overload(
                '[Ljava.security.cert.X509Certificate;', '[B', '[B',
                'java.lang.String', 'java.lang.String', 'boolean'
            ).implementation = function(chain, ocsp, tls, host, auth, srv) {
                console.log("[PHANTOM] checkTrusted2 BYPASSED: " + host);
                return Java.use('java.util.Arrays').asList(chain);
            };
            console.log("[PHANTOM] checkTrusted(bytes) hooked OK");
        } catch(e) {}

        // 2. OkHttp3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log("[PHANTOM] OkHttp3 CertificatePinner bypassed");
            };
        } catch(e) {}
        try {
            var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
            CertificatePinner2['check$okhttp'].implementation = function() {
                console.log("[PHANTOM] OkHttp3 CertificatePinner$okhttp bypassed");
            };
        } catch(e) {}

        // 3. SSLContext — inject permissive TrustManager
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var EmptyTM = Java.registerClass({
                name: 'com.phantom.ssl.EmptyTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function() {},
                    checkServerTrusted: function() {},
                    getAcceptedIssuers: function() { return []; },
                }
            });
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function(km, tm, sr) {
                console.log("[PHANTOM] SSLContext.init bypassed");
                this.init(km, [EmptyTM.$new()], sr);
            };
        } catch(e) {}

        // 4. HostnameVerifier
        try {
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var AlwaysTrue = Java.registerClass({
                name: 'com.phantom.ssl.TrueVerifier',
                implements: [HostnameVerifier],
                methods: {
                    verify: function() { return true; }
                }
            });
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultHostnameVerifier.call(
                HttpsURLConnection, AlwaysTrue.$new()
            );
        } catch(e) {}

        // 5. WebView SSL error bypass
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                console.log("[PHANTOM] WebView SSL error bypassed");
                handler.proceed();
            };
        } catch(e) {}

        // 6. Network security config bypass (Android 7+)
        try {
            var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
            NetworkSecurityConfig.isCleartextTrafficPermitted.overload().implementation = function() {
                return true;
            };
        } catch(e) {}

        // ===== OKHTTP PROXY INJECTION =====
        // Many apps don't respect Android system proxy — force it via Frida
        try {
            var InetSocketAddress = Java.use('java.net.InetSocketAddress');
            var Proxy = Java.use('java.net.Proxy');
            var ProxyType = Java.use('java.net.Proxy$Type');
            var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');

            OkHttpBuilder.build.implementation = function() {
                try {
                    var addr = InetSocketAddress.$new("10.0.2.2", MITMPROXY_PORT);
                    var proxy = Proxy.$new(ProxyType.HTTP.value, addr);
                    this.proxy(proxy);
                    console.log("[PHANTOM] OkHttp proxy injected → 10.0.2.2:MITMPROXY_PORT");
                } catch(e) {}
                return this.build();
            };
        } catch(e) {
            console.log("[PHANTOM] OkHttp proxy injection not available: " + e);
        }

        // ===== HTTP TRAFFIC INTERCEPTOR =====
        // Log requests that go through OkHttp (even if mitmproxy misses them)
        try {
            var RealCall = Java.use('okhttp3.internal.connection.RealCall');
            RealCall.getResponseWithInterceptorChain.implementation = function() {
                var req = this.getOriginalRequest();
                var url = req.url().toString();
                var method = req.method();
                console.log("[PHANTOM-HTTP] " + method + " " + url);
                return this.getResponseWithInterceptorChain();
            };
        } catch(e) {}
        try {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.getResponseCode.implementation = function() {
                var url = this.getURL().toString();
                console.log("[PHANTOM-HTTP] HttpURLConnection → " + url);
                return this.getResponseCode();
            };
        } catch(e) {}

        console.log("[PHANTOM] All Java hooks installed");
    });
}, 1000);
""".replace("MITMPROXY_PORT", str(MITMPROXY_PORT))

# ─── mitmproxy addon to capture traffic ───

MITM_ADDON_SCRIPT = '''
"""mitmproxy addon — captures all HTTP/S requests to a JSON file."""
import json
import os
import time

CAPTURE_FILE = os.environ.get("MITM_CAPTURE_FILE", "/tmp/phantom_mitm_capture.json")

class PhantomCapture:
    def __init__(self):
        self.requests = []

    def response(self, flow):
        entry = {
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text()[:2000] if flow.request.content else "",
            "status_code": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": flow.response.get_text()[:5000] if flow.response.content else "",
            "content_type": flow.response.headers.get("content-type", ""),
        }
        self.requests.append(entry)
        with open(CAPTURE_FILE, "w") as f:
            json.dump(self.requests, f, indent=2, default=str)

addons = [PhantomCapture()]
'''

# Skip these hosts (noise from Google Play Services, Firebase, etc.)
SKIP_HOSTS = {
    "connectivitycheck.gstatic.com", "play.googleapis.com",
    "www.googleapis.com", "android.clients.google.com",
    "mtalk.google.com", "fonts.googleapis.com",
    "firebaseinstallations.googleapis.com",
    "firebaselogging-pa.googleapis.com",
    "app-measurement.com", "firebase-settings.crashlytics.com",
    "settings.crashlytics.com", "device-provisioning.googleapis.com",
    "time.android.com", "ssl.gstatic.com",
    "accounts.google.com", "oauth2.googleapis.com",
}


class MobileDynamicScanner:
    """Runs APK in emulator, intercepts traffic, extracts real endpoints.

    All commands execute via SSH because backend runs in Docker
    while emulator/tools are on the host.
    """

    def __init__(self):
        self.frida_log = []
        # Remote (host) paths
        self.capture_file = "/tmp/phantom_mitm_capture.json"
        self.addon_file = "/tmp/phantom_mitm_addon.py"
        self.frida_script_file = "/tmp/phantom_frida_bypass.js"

    async def _ssh(self, cmd: str, timeout: int = 30) -> str:
        """Execute command on host via SSH."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ssh", *SSH_OPTS, "-i", SSH_KEY,
                f"{SSH_USER}@{SSH_HOST}", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
            return stdout.decode(errors="replace")
        except asyncio.TimeoutError:
            logger.debug(f"SSH timeout: {cmd[:80]}")
            return ""
        except Exception as e:
            logger.debug(f"SSH error: {e}")
            return ""

    async def _ssh_bg(self, cmd: str) -> None:
        """Execute command on host via SSH in background (nohup)."""
        bg_cmd = f"nohup {cmd} > /dev/null 2>&1 &"
        await self._ssh(bg_cmd, timeout=10)

    async def _scp_to_host(self, local_path: str, remote_path: str) -> bool:
        """Copy file from Docker container to host via SCP."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "scp", *SSH_OPTS, "-i", SSH_KEY,
                local_path, f"{SSH_USER}@{SSH_HOST}:{remote_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"SCP error: {e}")
            return False

    async def _ssh_read_file(self, remote_path: str) -> str:
        """Read file content from host via SSH."""
        return await self._ssh(f"cat {remote_path}", timeout=15)

    async def _ssh_write_file(self, remote_path: str, content: str) -> None:
        """Write file on host via SCP (avoids shell escaping issues)."""
        # Write to local temp file, then SCP to host
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as f:
            f.write(content)
            local_path = f.name
        try:
            await self._scp_to_host(local_path, remote_path)
        finally:
            os.unlink(local_path)

    async def scan(self, apk_path: str, package_name: str = "",
                   duration: int = 120) -> dict:
        """Full dynamic scan pipeline.

        Args:
            apk_path: Path to APK file
            package_name: Android package name (auto-detected if empty)
            duration: How long to run the app (seconds)

        Returns:
            Dict with captured_requests, endpoints, tokens, base_urls, etc.
        """
        result = {
            "captured_requests": [],
            "endpoints": [],
            "tokens": [],
            "base_urls": [],
            "headers_of_interest": [],
            "frida_http_log": [],
            "errors": [],
        }

        try:
            # Step 0: Transfer APK to host (backend runs in Docker)
            remote_apk = f"/tmp/phantom_scan_{int(time.time())}.apk"
            logger.info(f"Step 0: Transferring APK to host: {remote_apk}")
            if not await self._scp_to_host(apk_path, remote_apk):
                result["errors"].append("Failed to transfer APK to host via SCP")
                return result

            # Step 1: Ensure emulator is running
            logger.info("Step 1: Ensuring emulator is running...")
            if not await self._ensure_emulator():
                result["errors"].append("Failed to start Android emulator")
                return result

            # Step 2: Install mitmproxy CA cert as system cert
            logger.info("Step 2: Installing mitmproxy CA as system cert...")
            await self._install_system_ca()

            # Step 3: Install APK (from host path)
            logger.info(f"Step 3: Installing APK: {remote_apk}")
            if not package_name:
                package_name = await self._get_package_name(remote_apk)
            await self._install_apk(remote_apk)

            # Step 4: Set system proxy
            logger.info("Step 4: Setting system proxy...")
            await self._set_proxy()

            # Step 5: Start mitmproxy capture
            logger.info("Step 5: Starting mitmproxy...")
            await self._start_mitmproxy()

            # Step 6: Ensure frida-server is running
            logger.info("Step 6: Starting frida-server...")
            await self._ensure_frida_server()

            # Step 7: Launch app (BEFORE Frida — attach mode)
            logger.info(f"Step 7: Launching {package_name}...")
            await self._launch_app(package_name)
            await asyncio.sleep(8)  # Wait for app to fully initialize

            # Step 8: Attach Frida (attach mode — Java VM is ready)
            logger.info("Step 8: Attaching Frida SSL bypass + proxy injection...")
            await self._attach_frida(package_name)

            # Step 8b: Restart activity to trigger new requests with hooks active
            logger.info("Step 8b: Restarting activity with hooks active...")
            await self._restart_activity(package_name)
            await asyncio.sleep(10)

            # Step 9: Auto-interact with the app
            logger.info(f"Step 9: Auto-interacting for {duration}s...")
            await self._auto_interact(package_name, duration)

            # Step 10: Collect results
            logger.info("Step 10: Collecting captured traffic...")
            result = await self._collect_results(result)

            # Step 11: Collect Frida HTTP log (requests Frida intercepted)
            result["frida_http_log"] = self.frida_log

            # Step 12: Stop app
            logger.info("Step 12: Cleaning up...")
            await self._stop_app(package_name)

        except Exception as e:
            logger.error(f"Dynamic scan error: {e}", exc_info=True)
            result["errors"].append(str(e))
        finally:
            await self._cleanup_processes()
            # Clean remote APK
            await self._ssh(f"rm -f {remote_apk}")

        return result

    # ─── Emulator Management ─────────────────────────────────────────

    async def _ensure_emulator(self) -> bool:
        """Start emulator if not already running (via SSH to host)."""
        output = await self._adb("devices")
        if "emulator" in output:
            boot = await self._adb("shell", "getprop", "sys.boot_completed")
            if boot.strip() == "1":
                logger.info("Emulator already running and booted")
                return True

        # Check AVD exists on host
        check = await self._ssh(f"test -d {ANDROID_AVD_HOME}/{AVD_NAME}.avd && echo exists")
        if "exists" not in check:
            logger.info(f"Creating AVD: {AVD_NAME}")
            await self._create_avd()

        # Start emulator headless on host
        logger.info("Starting headless emulator on host...")
        emu_cmd = (
            f"ANDROID_HOME={ANDROID_HOME} ANDROID_AVD_HOME={ANDROID_AVD_HOME} "
            f"nohup {EMULATOR} @{AVD_NAME} "
            f"-no-window -no-audio -no-boot-anim "
            f"-gpu swiftshader_indirect -memory 2048 -no-snapshot-save "
            f"> /tmp/phantom_emulator.log 2>&1 &"
        )
        await self._ssh(emu_cmd, timeout=15)

        # Wait for boot (max 180s)
        for i in range(90):
            await asyncio.sleep(2)
            boot = await self._adb("shell", "getprop", "sys.boot_completed")
            if boot.strip() == "1":
                logger.info(f"Emulator booted in {(i+1)*2}s")
                await asyncio.sleep(5)
                return True

        logger.error("Emulator boot timeout (180s)")
        return False

    async def _create_avd(self):
        """Create Android Virtual Device on host."""
        avdmanager = os.path.join(
            ANDROID_HOME, "cmdline-tools", "latest", "bin", "avdmanager",
        )
        cmd = (
            f"ANDROID_HOME={ANDROID_HOME} ANDROID_AVD_HOME={ANDROID_AVD_HOME} "
            f"echo 'no' | {avdmanager} create avd "
            f"-n {AVD_NAME} -k 'system-images;android-34;google_apis;x86_64' "
            f"-d pixel_6 --force"
        )
        output = await self._ssh(cmd, timeout=60)
        logger.info(f"AVD created: {output[:200]}")

    async def _adb(self, *args) -> str:
        """Run adb command on host via SSH."""
        cmd = f"{ADB} {' '.join(args)}"
        return await self._ssh(cmd, timeout=30)

    async def _shell(self, cmd: str) -> str:
        """Run shell command on emulator via SSH+adb."""
        return await self._adb("shell", f"'{cmd}'")

    # ─── System CA Certificate ────────────────────────────────────────

    async def _install_system_ca(self):
        """Install mitmproxy CA as system cert using tmpfs overlay.

        All operations via SSH to host. Android 14+ has readonly /system.
        We use a tmpfs overlay.
        """
        # Check if CA cert exists on host
        ca_pem = f"/home/{SSH_USER}/.mitmproxy/mitmproxy-ca-cert.pem"
        check = await self._ssh(f"test -f {ca_pem} && echo exists")
        if "exists" not in check:
            logger.info("Generating mitmproxy CA cert on host...")
            await self._ssh(f"{TOOLS_BIN}/mitmdump --help > /dev/null 2>&1")
            check = await self._ssh(f"test -f {ca_pem} && echo exists")
            if "exists" not in check:
                logger.warning("mitmproxy CA cert not found — SSL intercept may fail")
                return

        # Get cert hash
        cert_hash = await self._ssh(
            f"openssl x509 -inform PEM -subject_hash_old -in {ca_pem} -noout"
        )
        cert_hash = cert_hash.strip()
        if not cert_hash:
            logger.warning("Failed to get cert hash")
            return

        cert_name = f"{cert_hash}.0"

        # Push PEM cert to emulator
        await self._ssh(f"{ADB} push {ca_pem} /sdcard/{cert_name}")

        # Run tmpfs overlay as root
        await self._ssh(f"{ADB} root")
        await asyncio.sleep(2)

        # Check if already installed
        check = await self._ssh(
            f"{ADB} shell ls /system/etc/security/cacerts/{cert_name} 2>/dev/null"
        )
        if cert_name in check:
            logger.info("mitmproxy CA cert already installed as system cert")
            return

        # Tmpfs overlay approach
        commands = [
            "mkdir -p /data/local/tmp/cacerts",
            "cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/",
            f"cp /sdcard/{cert_name} /data/local/tmp/cacerts/{cert_name}",
            f"chmod 644 /data/local/tmp/cacerts/{cert_name}",
            "mount -t tmpfs tmpfs /system/etc/security/cacerts",
            "cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/",
            "chmod 644 /system/etc/security/cacerts/*",
            "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*",
            "rm -rf /data/local/tmp/cacerts",
        ]
        for cmd in commands:
            await self._ssh(f"{ADB} shell '{cmd}'")

        logger.info(f"mitmproxy CA cert installed as system cert: {cert_name}")

    # ─── APK Management ──────────────────────────────────────────────

    async def _get_package_name(self, apk_path: str) -> str:
        """Extract package name from APK using aapt2 on host."""
        aapt2 = os.path.join(ANDROID_HOME, "build-tools", "34.0.0", "aapt2")
        output = await self._ssh(f"{aapt2} dump packagename {apk_path}", timeout=15)
        return output.strip()

    async def _install_apk(self, apk_path: str):
        """Install APK on emulator (APK is already on host)."""
        output = await self._adb("install", "-r", "-g", apk_path)
        if "Success" not in output:
            logger.warning(f"APK install issue: {output[:300]}")

    # ─── mitmproxy ───────────────────────────────────────────────────

    async def _start_mitmproxy(self):
        """Start mitmproxy on host as background process."""
        # Write addon script on host
        await self._ssh_write_file(self.addon_file, MITM_ADDON_SCRIPT)
        # Clear previous capture
        await self._ssh(f"echo '[]' > {self.capture_file}")

        # Kill any existing mitmproxy
        await self._ssh("pkill -f mitmdump 2>/dev/null; sleep 1")

        mitmdump = os.path.join(TOOLS_BIN, "mitmdump")
        cmd = (
            f"MITM_CAPTURE_FILE={self.capture_file} "
            f"nohup {mitmdump} -p {MITMPROXY_PORT} "
            f"-s {self.addon_file} "
            f"--set ssl_insecure=true --set connection_strategy=lazy "
            f"> /tmp/phantom_mitm.log 2>&1 &"
        )
        await self._ssh(cmd, timeout=10)
        await asyncio.sleep(3)
        logger.info(f"mitmproxy started on host port {MITMPROXY_PORT}")

    async def _set_proxy(self):
        """Configure emulator to use mitmproxy."""
        await self._adb("shell", "settings", "put", "global", "http_proxy",
                         f"10.0.2.2:{MITMPROXY_PORT}")

    # ─── Frida ───────────────────────────────────────────────────────

    async def _ensure_frida_server(self):
        """Ensure frida-server is running on emulator (via SSH)."""
        await self._ssh(f"{ADB} root")
        await asyncio.sleep(1)

        ps_out = await self._ssh(f"{ADB} shell 'ps -A | grep frida-server'")
        if "frida-server" in ps_out:
            logger.info("frida-server already running")
            return

        frida_server = "/data/local/tmp/frida-server"
        check = await self._ssh(f"{ADB} shell ls {frida_server}")
        if "No such file" in check:
            logger.warning(f"frida-server not found at {frida_server}")
            return

        await self._ssh(f"{ADB} shell chmod 755 {frida_server}")
        # Start frida-server in background on emulator
        await self._ssh(f"{ADB} shell 'nohup {frida_server} -D &' &")
        await asyncio.sleep(3)
        logger.info("frida-server started on emulator")

    async def _attach_frida(self, package_name: str):
        """Attach Frida CLI to running app (via SSH to host).

        Must use CLI frida (not Python API) — Python API doesn't set up
        the Java bridge properly. Attach by PID after 8s delay for Java VM.
        """
        # Write Frida script on host
        await self._ssh_write_file(self.frida_script_file, SSL_BYPASS_SCRIPT)

        frida_bin = os.path.join(TOOLS_BIN, "frida")

        # Get app PID
        pid_output = await self._ssh(f"{ADB} shell pidof {package_name}")
        app_pid = pid_output.strip()
        if not app_pid:
            logger.warning(f"App {package_name} not running — skipping Frida")
            return

        # Run Frida in background on host, capture output to log file
        frida_log = "/tmp/phantom_frida.log"
        cmd = (
            f"nohup {frida_bin} -D emulator-5554 "
            f"-l {self.frida_script_file} "
            f"-p {app_pid} "
            f"> {frida_log} 2>&1 &"
        )
        await self._ssh(cmd, timeout=10)
        await asyncio.sleep(5)

        # Read Frida output
        output = await self._ssh(f"cat {frida_log}", timeout=10)
        if output:
            logger.info(f"Frida output: {output[:500]}")
            if "hooked OK" in output or "HOOKS READY" in output:
                logger.info("Frida SSL bypass hooks installed successfully")
            elif "Java" in output and "not defined" in output:
                logger.warning("Java bridge not available")

        logger.info(f"Frida attached to {package_name} (PID {app_pid})")

    async def _read_frida_output(self):
        """Read Frida log from host for HTTP request logs."""
        output = await self._ssh("cat /tmp/phantom_frida.log 2>/dev/null", timeout=10)
        for line in output.split("\n"):
            line = line.strip()
            if "[PHANTOM-HTTP]" in line and line not in self.frida_log:
                self.frida_log.append(line)

    # ─── App Interaction ─────────────────────────────────────────────

    async def _launch_app(self, package_name: str):
        """Launch the app on emulator via SSH."""
        await self._adb("shell", f"am force-stop {package_name}")
        await asyncio.sleep(1)

        # Get main activity
        output = await self._ssh(
            f"{ADB} shell cmd package resolve-activity --brief {package_name}"
        )
        activity = ""
        for line in output.strip().split("\n"):
            if "/" in line:
                activity = line.strip()
                break

        if activity:
            await self._adb("shell", f"am start -n {activity}")
        else:
            await self._adb("shell",
                f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
        await asyncio.sleep(5)

    async def _restart_activity(self, package_name: str):
        """Restart main activity without killing process.

        Forces app to re-initialize network connections
        while Frida hooks are active.
        """
        output = await self._ssh(
            f"{ADB} shell cmd package resolve-activity --brief {package_name}"
        )
        activity = ""
        for line in output.strip().split("\n"):
            if "/" in line:
                activity = line.strip()
                break

        if activity:
            await self._adb("shell", f"am start --activity-clear-top -n {activity}")
        else:
            await self._adb("shell",
                f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
        logger.info(f"Activity restarted: {activity or package_name}")

    async def _auto_interact(self, package_name: str, duration: int):
        """Automated UI interaction via SSH — monkey events + taps/swipes."""
        start = time.time()
        interactions = 0

        while time.time() - start < duration:
            try:
                monkey_cmd = (
                    f"monkey -p {package_name} --throttle 1000 "
                    f"--pct-touch 40 --pct-motion 20 --pct-trackball 0 "
                    f"--pct-nav 20 --pct-majornav 10 --pct-syskeys 5 "
                    f"--pct-appswitch 5 --pct-anyevent 0 -v 20"
                )
                await self._adb("shell", monkey_cmd)
                interactions += 20
            except Exception:
                pass

            await self._adb("shell", "input swipe 500 1500 500 300")
            await asyncio.sleep(1)
            await self._adb("shell", "input tap 540 960")
            await asyncio.sleep(2)

            if interactions % 40 == 0:
                await self._adb("shell", "input keyevent KEYCODE_BACK")
                await asyncio.sleep(1)

            # Read Frida HTTP log
            await self._read_frida_output()

        logger.info(f"Auto-interaction: {interactions} events in {duration}s")

    async def _stop_app(self, package_name: str):
        """Stop the app."""
        await self._adb("shell", "am", "force-stop", package_name)

    # ─── Results Collection ──────────────────────────────────────────

    async def _collect_results(self, result: dict) -> dict:
        """Parse captured traffic and extract security-relevant data."""
        try:
            raw = await self._ssh_read_file(self.capture_file)
            captured = json.loads(raw) if raw.strip() else []
        except Exception:
            captured = []

        # Filter noise
        filtered = []
        for req in captured:
            host = req.get("host", "")
            if host in SKIP_HOSTS:
                continue
            if any(host.endswith(s) for s in (
                ".google.com", ".gstatic.com", ".googleapis.com",
                ".google-analytics.com", ".doubleclick.net",
                ".googleadservices.com", ".facebook.com",
            )):
                continue
            filtered.append(req)

        result["captured_requests"] = filtered
        result["total_captured"] = len(captured)
        result["filtered_count"] = len(filtered)

        # Extract unique endpoints
        seen = set()
        for req in filtered:
            method = req.get("method", "GET")
            path = req.get("path", "")
            key = f"{method}:{path}"
            if key not in seen:
                seen.add(key)
                auth = req.get("request_headers", {}).get("Authorization", "")
                result["endpoints"].append({
                    "method": method,
                    "url": req.get("url", ""),
                    "path": path,
                    "auth": auth[:50] if auth else "",
                    "status": req.get("status_code"),
                    "content_type": req.get("content_type", ""),
                })

        # Extract tokens and auth headers
        token_values = set()
        for req in filtered:
            headers = req.get("request_headers", {})
            for key, value in headers.items():
                kl = key.lower()
                if kl in ("authorization", "x-auth-token", "x-api-key",
                          "x-access-token", "cookie", "x-csrf-token"):
                    if value not in token_values:
                        token_values.add(value)
                        result["tokens"].append({
                            "header": key,
                            "value": value[:200],
                            "host": req.get("host", ""),
                        })
                if kl.startswith("x-") and kl not in (
                    "x-requested-with", "x-forwarded-for",
                    "x-cloud-trace-context",
                ):
                    result["headers_of_interest"].append({
                        "header": key,
                        "value": value[:100],
                        "host": req.get("host", ""),
                    })

        # Extract base URLs
        seen_bases = set()
        for req in filtered:
            url = req.get("url", "")
            if "://" in url:
                parts = url.split("/")
                if len(parts) >= 3:
                    base = "/".join(parts[:3])
                    seen_bases.add(base)
        result["base_urls"] = sorted(seen_bases)

        # Detect sensitive data in responses
        sensitive_patterns = {
            "jwt_token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            "api_key": r'(?:api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_-]{20,})',
            "password_field": r'"password"\s*:\s*"[^"]+',
            "access_token": r'access[_-]?token["\s:=]+["\']?([A-Za-z0-9_.-]{20,})',
            "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        }
        sensitive_finds = []
        for req in filtered:
            body = req.get("response_body", "")
            for name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    sensitive_finds.append({
                        "type": name,
                        "url": req.get("url", ""),
                        "count": len(matches),
                    })
        result["sensitive_data"] = sensitive_finds

        logger.info(
            f"Dynamic scan: {len(filtered)} requests, "
            f"{len(result['endpoints'])} endpoints, "
            f"{len(result['tokens'])} tokens, "
            f"{len(result['base_urls'])} base URLs, "
            f"{len(sensitive_finds)} sensitive data finds"
        )

        return result

    # ─── Cleanup ─────────────────────────────────────────────────────

    async def _cleanup_processes(self):
        """Stop mitmproxy and frida on host (keep emulator running)."""
        await self._ssh("pkill -f mitmdump 2>/dev/null")
        await self._ssh("pkill -f 'frida -D' 2>/dev/null")
        logger.info("mitmproxy + frida stopped on host")

        # Reset proxy on emulator
        await self._adb("shell", "settings put global http_proxy :0")

        # Clean temp files on host
        await self._ssh(
            f"rm -f {self.addon_file} {self.frida_script_file} /tmp/phantom_frida.log"
        )

    # ─── Status ──────────────────────────────────────────────────────

    async def is_emulator_running(self) -> bool:
        """Check if emulator is running and booted (via SSH)."""
        output = await self._adb("devices")
        if "emulator" not in output:
            return False
        boot = await self._adb("shell", "getprop sys.boot_completed")
        return boot.strip() == "1"

    async def stop_emulator(self):
        """Stop the emulator."""
        await self._adb("emu", "kill")
