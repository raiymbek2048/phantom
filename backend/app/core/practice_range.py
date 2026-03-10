"""
Practice Range — Auto-deploy and scan vulnerable training targets.

Manages Docker containers for practice targets:
1. DVWA — PHP/MySQL classic web vulns
2. Juice Shop — Node.js modern app (OWASP)
3. WebGoat — Java (deserialization, XXE, JWT)
4. bWAPP — PHP (100+ vulns)
5. HackTheBox / custom — extensible

Each target has:
- Docker image + network config
- Setup script (auto-login, seed data)
- Expected vulnerabilities list (for scoring)
- Difficulty level
"""
import asyncio
import logging
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# Practice target definitions
PRACTICE_TARGETS = {
    "dvwa": {
        "name": "DVWA",
        "description": "Damn Vulnerable Web Application — PHP/MySQL classic vulns",
        "image": "vulnerables/web-dvwa",
        "internal_port": 80,
        "host_port": 4280,
        "difficulty": "beginner",
        "technologies": ["php", "apache", "mysql"],
        "setup": {
            "login_url": "/login.php",
            "login_method": "POST",
            "login_data": {"username": "admin", "password": "password"},
            "setup_url": "/setup.php",
            "setup_action": "create_db",
        },
        "expected_vulns": {
            "sqli_blind": {"count": 2, "paths": ["/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/"]},
            "xss_reflected": {"count": 2, "paths": ["/vulnerabilities/xss_r/"]},
            "xss_stored": {"count": 1, "paths": ["/vulnerabilities/xss_s/"]},
            "cmd_injection": {"count": 1, "paths": ["/vulnerabilities/exec/"]},
            "csrf": {"count": 1, "paths": ["/vulnerabilities/csrf/"]},
            "rce": {"count": 1, "paths": ["/vulnerabilities/upload/"]},
            "info_disclosure": {"count": 1, "paths": ["/vulnerabilities/fi/", "/"]},
            "misconfiguration": {"count": 2, "paths": ["/"]},
        },
        "total_expected": 11,
    },
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "description": "Modern Node.js vulnerable app with 100+ challenges",
        "image": "bkimminich/juice-shop",
        "internal_port": 3000,
        "host_port": 3001,
        "difficulty": "intermediate",
        "technologies": ["node", "angular", "sqlite", "express"],
        "setup": {
            "login_url": "/rest/user/login",
            "login_method": "POST",
            "login_data": {"email": "admin@juice-sh.op", "password": "admin123"},
            "content_type": "application/json",
        },
        "expected_vulns": {
            "sqli": {"count": 3, "paths": ["/rest/user/login", "/rest/products/search"]},
            "xss_reflected": {"count": 2, "paths": ["/"]},
            "idor": {"count": 3, "paths": ["/api/Users/", "/api/BasketItems/"]},
            "ssrf": {"count": 1, "paths": ["/profile/image/url"]},
            "info_disclosure": {"count": 2, "paths": ["/ftp/", "/api/"]},
            "lfi": {"count": 2, "paths": ["/ftp/"]},
        },
        "total_expected": 13,
    },
    "webgoat": {
        "name": "WebGoat",
        "description": "Java OWASP training — deserialization, XXE, JWT, crypto",
        "image": "webgoat/webgoat",
        "internal_port": 8080,
        "host_port": 8081,
        "difficulty": "advanced",
        "technologies": ["java", "spring", "h2"],
        "setup": {
            "register_url": "/WebGoat/register.mvc",
            "register_method": "POST",
            "register_data": {
                "username": "phantom", "password": "phantom123",
                "matchingPassword": "phantom123", "agree": "agree",
            },
            "login_url": "/WebGoat/login",
            "login_method": "POST",
            "login_data": {"username": "phantom", "password": "phantom123"},
        },
        "expected_vulns": {
            "sqli": {"count": 2, "paths": ["/WebGoat/SqlInjection/"]},
            "xxe": {"count": 1, "paths": ["/WebGoat/xxe/"]},
            "deserialization": {"count": 1, "paths": ["/WebGoat/InsecureDeserialization/"]},
            "xss_reflected": {"count": 1, "paths": ["/WebGoat/CrossSiteScripting/"]},
            "idor": {"count": 1, "paths": ["/WebGoat/IDOR/"]},
            "csrf": {"count": 1, "paths": ["/WebGoat/csrf/"]},
            "misconfig": {"count": 1, "paths": ["/WebGoat/"]},
        },
        "total_expected": 8,
    },
    "bwapp": {
        "name": "bWAPP",
        "description": "Buggy Web Application — 100+ vulnerabilities across all categories",
        "image": "raesene/bwapp",
        "internal_port": 80,
        "host_port": 4281,
        "difficulty": "beginner",
        "technologies": ["php", "apache", "mysql"],
        "setup": {
            "install_url": "/install.php?install=yes",
            "login_url": "/login.php",
            "login_method": "POST",
            "login_data": {"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
        },
        "expected_vulns": {
            "sqli": {"count": 3, "paths": ["/sqli_1.php", "/sqli_2.php"]},
            "xss_reflected": {"count": 3, "paths": ["/xss_get.php", "/xss_post.php"]},
            "cmd_injection": {"count": 2, "paths": ["/commandi.php"]},
            "lfi": {"count": 2, "paths": ["/rlfi.php"]},
            "ssrf": {"count": 1, "paths": ["/ssrf-1.php"]},
            "xxe": {"count": 1, "paths": ["/xxe-1.php"]},
            "csrf": {"count": 1, "paths": ["/csrf_1.php"]},
        },
        "total_expected": 13,
    },
}


class PracticeRange:
    """Manages practice targets for AI training."""

    def __init__(self):
        self.docker_available = None

    async def check_docker(self) -> bool:
        """Check if Docker is available."""
        if self.docker_available is not None:
            return self.docker_available
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "version", "--format", "{{.Server.Version}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            self.docker_available = proc.returncode == 0
        except FileNotFoundError:
            self.docker_available = False
        return self.docker_available

    async def list_targets(self) -> list[dict]:
        """List all available practice targets and their status."""
        targets = []
        for key, config in PRACTICE_TARGETS.items():
            status = await self._check_target_status(key, config)
            targets.append({
                "id": key,
                "name": config["name"],
                "description": config["description"],
                "difficulty": config["difficulty"],
                "technologies": config["technologies"],
                "total_expected_vulns": config["total_expected"],
                "host_port": config["host_port"],
                "status": status,
            })
        return targets

    async def _check_target_status(self, key: str, config: dict) -> str:
        """Check if a practice target is running."""
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                resp = await client.get(f"http://localhost:{config['host_port']}/")
                if resp.status_code < 500:
                    return "running"
        except Exception:
            pass

        # Check if container exists but stopped
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "ps", "-a", "--filter", f"name={key}",
                "--format", "{{.Status}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            status_text = stdout.decode().strip()
            if "Up" in status_text:
                return "running"
            elif status_text:
                return "stopped"
        except Exception:
            pass

        return "not_deployed"

    async def deploy_target(self, target_id: str, network: str = "phantom_default") -> dict:
        """Deploy a practice target container."""
        if target_id not in PRACTICE_TARGETS:
            return {"success": False, "error": f"Unknown target: {target_id}"}

        config = PRACTICE_TARGETS[target_id]

        if not await self.check_docker():
            return {"success": False, "error": "Docker is not available"}

        # Check if already running
        status = await self._check_target_status(target_id, config)
        if status == "running":
            return {"success": True, "message": f"{config['name']} is already running",
                    "url": f"http://localhost:{config['host_port']}"}

        # Stop old container if exists
        if status == "stopped":
            await self._run_cmd("docker", "rm", "-f", target_id)

        # Pull image
        logger.info(f"Pulling {config['image']}...")
        await self._run_cmd("docker", "pull", config["image"])

        # Run container
        cmd = [
            "docker", "run", "-d",
            "--name", target_id,
            "--network", network,
            "-p", f"{config['host_port']}:{config['internal_port']}",
            "--restart", "unless-stopped",
            config["image"],
        ]
        result = await self._run_cmd(*cmd)
        if result["returncode"] != 0:
            return {"success": False, "error": result["stderr"]}

        # Wait for it to be ready
        logger.info(f"Waiting for {config['name']} to start...")
        ready = await self._wait_for_ready(config["host_port"], timeout=60)

        if not ready:
            return {"success": False, "error": f"{config['name']} did not start within 60s"}

        # Run setup if needed
        setup_result = await self._setup_target(target_id, config)

        return {
            "success": True,
            "message": f"{config['name']} deployed and ready",
            "url": f"http://localhost:{config['host_port']}",
            "internal_url": f"http://{target_id}:{config['internal_port']}",
            "setup": setup_result,
        }

    async def stop_target(self, target_id: str) -> dict:
        """Stop and remove a practice target."""
        result = await self._run_cmd("docker", "rm", "-f", target_id)
        return {
            "success": result["returncode"] == 0,
            "message": f"{target_id} stopped" if result["returncode"] == 0 else result["stderr"],
        }

    async def deploy_all(self, network: str = "phantom_default") -> list[dict]:
        """Deploy all practice targets."""
        results = []
        for target_id in PRACTICE_TARGETS:
            result = await self.deploy_target(target_id, network)
            results.append({"target": target_id, **result})
        return results

    async def score_scan(self, target_id: str, vulns_found: list[dict]) -> dict:
        """Score a scan against expected vulnerabilities for a practice target."""
        if target_id not in PRACTICE_TARGETS:
            return {"error": "Unknown target"}

        config = PRACTICE_TARGETS[target_id]
        expected = config["expected_vulns"]

        # Map found vulns by type
        found_by_type = {}
        for v in vulns_found:
            vt = v.get("vuln_type", "")
            vt_val = vt.value if hasattr(vt, "value") else str(vt)
            if vt_val not in found_by_type:
                found_by_type[vt_val] = []
            found_by_type[vt_val].append(v)

        # Score each category
        categories = {}
        total_found = 0
        total_expected = config["total_expected"]

        for vuln_type, expected_data in expected.items():
            found = found_by_type.get(vuln_type, [])
            found_count = len(found)
            expected_count = expected_data["count"]

            score = min(1.0, found_count / expected_count) if expected_count > 0 else 0
            total_found += min(found_count, expected_count)

            categories[vuln_type] = {
                "expected": expected_count,
                "found": found_count,
                "score": round(score * 100, 1),
                "status": "complete" if found_count >= expected_count else
                         "partial" if found_count > 0 else "missed",
            }

        # Bonus: unexpected vulns found
        unexpected_types = set(found_by_type.keys()) - set(expected.keys())
        bonus_vulns = sum(len(found_by_type[t]) for t in unexpected_types)

        overall_score = round((total_found / total_expected * 100) if total_expected > 0 else 0, 1)

        return {
            "target": config["name"],
            "difficulty": config["difficulty"],
            "overall_score": overall_score,
            "total_found": total_found,
            "total_expected": total_expected,
            "bonus_vulns": bonus_vulns,
            "categories": categories,
            "grade": "A+" if overall_score >= 95 else
                    "A" if overall_score >= 85 else
                    "B" if overall_score >= 70 else
                    "C" if overall_score >= 50 else
                    "D" if overall_score >= 30 else "F",
        }

    async def _setup_target(self, target_id: str, config: dict) -> dict:
        """Run initial setup for a practice target (DB creation, etc)."""
        setup = config.get("setup", {})
        if not setup:
            return {"status": "no_setup_needed"}

        base_url = f"http://localhost:{config['host_port']}"

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                # Run install/setup URL if defined
                if "install_url" in setup:
                    await client.get(f"{base_url}{setup['install_url']}")

                if "setup_url" in setup:
                    await client.post(
                        f"{base_url}{setup['setup_url']}",
                        data={setup.get("setup_action", "submit"): "submit"},
                    )

                # Register if needed
                if "register_url" in setup:
                    await client.post(
                        f"{base_url}{setup['register_url']}",
                        data=setup["register_data"],
                    )

                # Login
                if "login_url" in setup:
                    headers = {}
                    if setup.get("content_type") == "application/json":
                        headers["Content-Type"] = "application/json"
                        resp = await client.post(
                            f"{base_url}{setup['login_url']}",
                            json=setup["login_data"],
                            headers=headers,
                        )
                    else:
                        resp = await client.post(
                            f"{base_url}{setup['login_url']}",
                            data=setup["login_data"],
                        )

                    if resp.status_code < 400:
                        return {"status": "setup_complete", "login": "success"}
                    return {"status": "setup_complete", "login": "failed", "code": resp.status_code}

        except Exception as e:
            return {"status": "setup_error", "error": str(e)}

        return {"status": "setup_complete"}

    async def _wait_for_ready(self, port: int, timeout: int = 60) -> bool:
        """Wait for a service to be ready on a port."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                    resp = await client.get(f"http://localhost:{port}/")
                    if resp.status_code < 500:
                        return True
            except Exception:
                pass
            await asyncio.sleep(2)
        return False

    async def _run_cmd(self, *args) -> dict:
        """Run a shell command and return result."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            return {
                "returncode": proc.returncode,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            }
        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": str(e)}

    def get_target_config(self, target_id: str) -> dict | None:
        """Get config for a specific practice target."""
        return PRACTICE_TARGETS.get(target_id)

    def get_internal_url(self, target_id: str) -> str | None:
        """Get internal Docker URL for a target."""
        config = PRACTICE_TARGETS.get(target_id)
        if not config:
            return None
        return f"http://{target_id}:{config['internal_port']}"
