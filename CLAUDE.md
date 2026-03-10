# PHANTOM — AI-Powered Penetration Testing Platform

## What is this project
PHANTOM is an autonomous AI pentester — a full-stack platform that scans websites for vulnerabilities like a professional penetration tester. It discovers subdomains, ports, technologies, endpoints, then actively attacks: brute-forces logins, tests services, checks for sensitive files, generates payloads, bypasses WAFs, and uses Claude AI for deep collaborative analysis.

## Tech Stack
- **Backend**: FastAPI + Celery + Redis + PostgreSQL (all in Docker)
- **Frontend**: Next.js 14 + TailwindCSS + Zustand (dark theme, hacker aesthetic)
- **AI**: Claude Max OAuth → Ollama (qwen2.5-coder:7b) → hardcoded fallback
- **Infra**: Docker Compose, nginx reverse proxy, WebSocket for live scan events

## Project Structure
```
phantom/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routers (auth, targets, scans, vulns, training, notifications...)
│   │   ├── ai/           # LLM engine, Claude collaboration, prompt templates
│   │   ├── core/         # Pipeline, orchestrator, training, knowledge, attack router, WAF intel, notifications
│   │   ├── models/       # SQLAlchemy models (Target, Scan, Vulnerability, User, Knowledge...)
│   │   ├── modules/      # Scan modules (recon, subdomain, portscan, endpoint, exploit, auth_attack, stress_test...)
│   │   └── utils/        # HTTP client, helpers
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/          # Next.js pages (targets, scans, vulns, training, settings, timeline...)
│   │   ├── components/   # Sidebar, ScanProgress, LoginForm, VulnCard...
│   │   └── lib/          # api.ts (all API functions), store.ts (Zustand), utils.ts
│   └── Dockerfile
├── docker-compose.yml
├── nginx.conf
└── sync-claude-token.sh
```

## 19-Phase Scan Pipeline
recon → subdomain → portscan → fingerprint → **attack_routing** → endpoint → **sensitive_files** → vuln_scan → nuclei → ai_analysis → payload_gen → waf → exploit → **service_attack** → **auth_attack** → **stress_test** → claude_collab → evidence → report

## Key Development Rules
1. **VulnType enum**: Always use `.value` for string comparison. Values: `xss`, `sqli`, `ssrf`, `info_disclosure`, `auth_bypass`, `misconfiguration` (NOT "misconfig" or "broken_auth")
2. **Severity enum**: `critical`, `high`, `medium`, `low`, `info`
3. **Rate limit pattern**: `self.context.get("rate_limit") or 5` (NOT `self.context.get("rate_limit", 5)` — returns None when key exists with None value)
4. **Celery + AsyncIO**: Always `reset_engine()` per task, wrap in `asyncio.run()`
5. **PostgreSQL enums**: Must `ALTER TYPE` to add new values, can't just add to Python enum
6. **Route ordering**: Static routes (`/export`, `/lifecycle`) BEFORE dynamic `/{id}` in FastAPI
7. **Pipeline findings**: New attack modules save findings directly as Vulnerability DB records (not to scan_results list)
8. **Docker**: Rebuild with `docker compose build backend celery_worker frontend`, then `docker compose up -d`, then `docker compose restart nginx`

## How to Run
```bash
cd phantom
docker compose up -d          # Start all services
./sync-claude-token.sh        # Sync Claude OAuth token from Keychain to Redis
# Frontend: http://localhost (via nginx)
# API: http://localhost/api
# Login: admin / changeme
```

## Important Context
- This is a WHITE HAT / authorized security testing tool
- All attack modules are bounded and controlled (max ~100 concurrent requests)
- The owner (user) speaks Russian, keep communication concise
- Before every session: read `memory/last_session.md` for context on what was done and what's next
- After every session: UPDATE `memory/last_session.md` with session summary
