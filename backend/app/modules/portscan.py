"""
Port Scanning & Service Detection Module

Capabilities:
1. Quick Scan — common web ports (-sV -sC on top ports)
2. Deep Scan — full 65535 port scan with service detection
3. OS Detection — nmap -O fingerprinting
4. Vulnerability Scripts — nmap NSE vuln scripts
5. UDP Scan — key UDP services (DNS, SNMP, NTP)
6. Firewall Detection — ACK scan, fragmentation
"""
import asyncio
import json
import logging
import re
import xml.etree.ElementTree as ET

from app.utils.tool_runner import run_command

logger = logging.getLogger(__name__)


class PortScanModule:
    # Common web ports for quick scan
    QUICK_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,9443,27017"

    # Top 1000 ports for standard scan (nmap default)
    # Full scan uses -p-

    # Dangerous services that indicate security risk
    RISKY_SERVICES = {
        "telnet": {"severity": "high", "reason": "Unencrypted remote access"},
        "ftp": {"severity": "medium", "reason": "Often allows anonymous access"},
        "vnc": {"severity": "high", "reason": "Remote desktop access"},
        "mysql": {"severity": "medium", "reason": "Database exposed to network"},
        "postgresql": {"severity": "medium", "reason": "Database exposed to network"},
        "mongodb": {"severity": "high", "reason": "Often lacks authentication by default"},
        "redis": {"severity": "high", "reason": "Often lacks authentication by default"},
        "elasticsearch": {"severity": "high", "reason": "Often lacks authentication"},
        "memcached": {"severity": "medium", "reason": "No authentication by default"},
        "docker": {"severity": "critical", "reason": "Docker API exposed — full host access"},
        "kubernetes": {"severity": "critical", "reason": "Kubernetes API exposed"},
        "smb": {"severity": "medium", "reason": "SMB file sharing exposed"},
        "rpc": {"severity": "low", "reason": "RPC services exposed"},
        "snmp": {"severity": "medium", "reason": "SNMP may leak system info"},
    }

    # NSE vulnerability scripts to run
    VULN_SCRIPTS = [
        "vuln",
        "ssl-heartbleed",
        "ssl-poodle",
        "ssl-drown",
        "ssl-enum-ciphers",
        "http-shellshock",
        "smb-vuln-ms17-010",
        "http-vuln-cve2017-5638",
    ]

    async def run(self, targets: list[str], scan_type: str = "quick") -> dict:
        """Scan ports for multiple targets.
        scan_type: 'quick' (common ports), 'standard' (top 1000), 'deep' (all 65535)
        """
        results = {}
        semaphore = asyncio.Semaphore(3)

        async def scan_with_limit(target):
            async with semaphore:
                return target, await self._scan_target(target, scan_type)

        tasks = [scan_with_limit(t) for t in targets]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, tuple):
                target, data = result
                if data:
                    results[target] = data

        return results

    async def _scan_target(self, target: str, scan_type: str = "quick") -> dict:
        """Scan a single target with configurable depth."""
        # Build nmap command based on scan type
        base_cmd = ["nmap", "-sV", "-sC", "--open", "-T4", "--max-retries", "2"]

        if scan_type == "quick":
            base_cmd.extend(["-p", self.QUICK_PORTS])
            timeout = 120
        elif scan_type == "standard":
            base_cmd.extend(["--top-ports", "1000"])
            timeout = 300
        elif scan_type == "deep":
            base_cmd.extend(["-p-"])
            timeout = 900
        else:
            base_cmd.extend(["-p", self.QUICK_PORTS])
            timeout = 120

        # Use XML output for better parsing
        base_cmd.extend(["-oX", "-", target])

        output = await run_command(base_cmd, timeout=timeout)
        if not output:
            return {}

        # Try XML parsing first, fall back to text
        ports = self._parse_nmap_xml(output)
        if not ports:
            ports = self._parse_nmap_output(output)

        # Analyze findings
        open_ports = ports
        risky = self._check_risky_services(open_ports)
        summary = self._build_summary(open_ports)

        result = {
            "ports": open_ports,
            "total_open": len(open_ports),
            "risky_services": risky,
            "summary": summary,
        }

        # Run OS detection if we found open ports
        if open_ports and scan_type in ("standard", "deep"):
            os_info = await self._detect_os(target)
            if os_info:
                result["os_detection"] = os_info

        return result

    async def deep_scan(self, target: str, ports: list[int] = None) -> dict:
        """Run deep vulnerability scan on specific ports using NSE scripts."""
        findings = []

        port_str = ",".join(str(p) for p in ports) if ports else self.QUICK_PORTS

        # Run vuln scripts
        scripts = ",".join(self.VULN_SCRIPTS)
        output = await run_command(
            ["nmap", "-sV", "--script", scripts,
             "-p", port_str, "-oX", "-", target],
            timeout=300,
        )

        if output:
            script_results = self._parse_nse_results(output)
            findings.extend(script_results)

        # SSL/TLS analysis on HTTPS ports
        ssl_ports = [p for p in (ports or [443, 8443]) if p in (443, 8443, 9443)]
        if ssl_ports:
            ssl_findings = await self._check_ssl(target, ssl_ports)
            findings.extend(ssl_findings)

        return {
            "target": target,
            "findings": findings,
            "scripts_run": self.VULN_SCRIPTS,
        }

    async def udp_scan(self, target: str) -> list[dict]:
        """Scan key UDP ports."""
        udp_ports = "53,69,123,161,162,500,514,1900,5353"
        output = await run_command(
            ["nmap", "-sU", "--open", "-p", udp_ports,
             "-T4", "--max-retries", "1", target],
            timeout=120,
        )

        if not output:
            return []

        return self._parse_nmap_output(output)

    async def _detect_os(self, target: str) -> dict | None:
        """Detect operating system using nmap fingerprinting."""
        output = await run_command(
            ["nmap", "-O", "--osscan-guess", target],
            timeout=60,
        )

        if not output:
            return None

        os_info = {}
        for line in output.split("\n"):
            line = line.strip()
            if "OS details:" in line:
                os_info["details"] = line.split("OS details:", 1)[1].strip()
            elif "Running:" in line:
                os_info["running"] = line.split("Running:", 1)[1].strip()
            elif "Aggressive OS guesses:" in line:
                os_info["guesses"] = line.split("Aggressive OS guesses:", 1)[1].strip()

        return os_info if os_info else None

    async def _check_ssl(self, target: str, ports: list[int]) -> list[dict]:
        """Check SSL/TLS configuration on HTTPS ports."""
        findings = []
        for port in ports:
            output = await run_command(
                ["nmap", "--script", "ssl-enum-ciphers,ssl-cert",
                 "-p", str(port), target],
                timeout=30,
            )
            if not output:
                continue

            # Check for weak ciphers
            if "TLSv1.0" in output:
                findings.append({
                    "title": f"TLS 1.0 Supported on port {port}",
                    "port": port,
                    "severity": "medium",
                    "vuln_type": "misconfig",
                    "impact": "TLS 1.0 is deprecated and has known vulnerabilities.",
                    "remediation": "Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                })

            if "SSLv3" in output:
                findings.append({
                    "title": f"SSLv3 Supported on port {port} (POODLE)",
                    "port": port,
                    "severity": "high",
                    "vuln_type": "misconfig",
                    "impact": "SSLv3 is vulnerable to POODLE attack.",
                    "remediation": "Disable SSLv3 entirely.",
                })

            # Weak ciphers
            weak_ciphers = re.findall(r"(RC4|DES|NULL|EXPORT|anon)", output)
            if weak_ciphers:
                findings.append({
                    "title": f"Weak SSL Ciphers on port {port}",
                    "port": port,
                    "severity": "medium",
                    "vuln_type": "misconfig",
                    "impact": f"Weak ciphers detected: {', '.join(set(weak_ciphers))}",
                    "remediation": "Disable weak cipher suites. Use strong ciphers only.",
                })

            # Self-signed or expired cert
            if "self-signed" in output.lower():
                findings.append({
                    "title": f"Self-Signed Certificate on port {port}",
                    "port": port,
                    "severity": "low",
                    "vuln_type": "misconfig",
                    "impact": "Self-signed certificate — no CA trust chain.",
                    "remediation": "Use a certificate from a trusted CA.",
                })

        return findings

    def _check_risky_services(self, ports: list[dict]) -> list[dict]:
        """Identify risky services from scan results."""
        risky = []
        for port in ports:
            service = port.get("service", "").lower()
            for svc_name, risk_info in self.RISKY_SERVICES.items():
                if svc_name in service:
                    risky.append({
                        "port": port["port"],
                        "service": port["service"],
                        "version": port.get("version", ""),
                        "severity": risk_info["severity"],
                        "reason": risk_info["reason"],
                    })
                    break
        return risky

    def _build_summary(self, ports: list[dict]) -> dict:
        """Build scan summary."""
        services = {}
        for p in ports:
            svc = p.get("service", "unknown")
            services[svc] = services.get(svc, 0) + 1

        web_ports = [p for p in ports if p.get("service") in ("http", "https", "http-proxy")]
        db_ports = [p for p in ports if p.get("service") in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch")]

        return {
            "total_open": len(ports),
            "web_services": len(web_ports),
            "database_services": len(db_ports),
            "service_types": services,
            "web_ports": [p["port"] for p in web_ports],
            "db_ports": [p["port"] for p in db_ports],
        }

    def _parse_nmap_xml(self, xml_output: str) -> list[dict]:
        """Parse nmap XML output for better structured data."""
        ports = []
        try:
            # Find XML content in output
            xml_start = xml_output.find("<?xml")
            if xml_start < 0:
                return []

            root = ET.fromstring(xml_output[xml_start:])

            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port_elem.find("service")
                        port_data = {
                            "port": int(port_elem.get("portid", 0)),
                            "protocol": port_elem.get("protocol", "tcp"),
                            "service": service.get("name", "unknown") if service is not None else "unknown",
                            "version": "",
                        }
                        if service is not None:
                            version_parts = []
                            if service.get("product"):
                                version_parts.append(service.get("product"))
                            if service.get("version"):
                                version_parts.append(service.get("version"))
                            if service.get("extrainfo"):
                                version_parts.append(f"({service.get('extrainfo')})")
                            port_data["version"] = " ".join(version_parts)

                        ports.append(port_data)

        except ET.ParseError:
            pass

        return ports

    def _parse_nmap_output(self, output: str) -> list[dict]:
        """Parse nmap text output into structured data."""
        ports = []
        pattern = r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)"

        for line in output.split("\n"):
            match = re.match(pattern, line.strip())
            if match:
                port_num, protocol, service, version = match.groups()
                ports.append({
                    "port": int(port_num),
                    "protocol": protocol,
                    "service": service,
                    "version": version.strip(),
                })

        return ports

    def _parse_nse_results(self, xml_output: str) -> list[dict]:
        """Parse NSE script results from XML output."""
        findings = []
        try:
            xml_start = xml_output.find("<?xml")
            if xml_start < 0:
                return []

            root = ET.fromstring(xml_output[xml_start:])

            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    port_id = port_elem.get("portid", "")

                    for script in port_elem.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")

                        # Check for vulnerability indicators
                        if any(kw in script_output.lower() for kw in
                               ("vulnerable", "vuln", "exploit", "compromised")):
                            severity = "high"
                            if "critical" in script_output.lower():
                                severity = "critical"

                            findings.append({
                                "title": f"NSE: {script_id} on port {port_id}",
                                "port": int(port_id) if port_id.isdigit() else 0,
                                "severity": severity,
                                "vuln_type": "misconfig",
                                "script": script_id,
                                "output": script_output[:500],
                                "impact": f"Nmap NSE script {script_id} detected a vulnerability on port {port_id}.",
                                "remediation": "Review the vulnerability details and apply vendor patches.",
                            })

        except ET.ParseError:
            pass

        return findings
