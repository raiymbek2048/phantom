#!/bin/bash
set -e

echo "========================================="
echo "  PHANTOM - AI Pentester Setup"
echo "========================================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "[ERROR] Docker Compose is not installed."
    exit 1
fi

echo "[+] Docker found"

# Create .env from example if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[+] Created .env file from .env.example"
    echo "[!] IMPORTANT: Edit .env and set your API keys"
else
    echo "[+] .env file already exists"
fi

# Create results directory
mkdir -p results/evidence

# Build and start services
echo ""
echo "[+] Building Docker images..."
docker compose build

echo ""
echo "[+] Starting services..."
docker compose up -d db redis

echo "[+] Waiting for database..."
sleep 5

echo "[+] Starting backend..."
docker compose up -d backend celery_worker

echo "[+] Starting Ollama..."
docker compose up -d ollama

echo ""
echo "[+] Pulling local LLM model (this may take a while)..."
docker compose exec ollama ollama pull llama3:8b || echo "[!] Could not pull model. Run manually: docker compose exec ollama ollama pull llama3:8b"

echo ""
echo "========================================="
echo "  PHANTOM is ready!"
echo "========================================="
echo ""
echo "  API:       http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo "  Dashboard: http://localhost:3000 (when frontend is built)"
echo ""
echo "  Next steps:"
echo "  1. Edit .env with your API keys"
echo "  2. Register a user: POST /api/auth/register"
echo "  3. Add a target: POST /api/targets"
echo "  4. Start scanning: POST /api/scans"
echo ""
