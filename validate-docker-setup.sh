#!/bin/bash

# Manus Attack Platform - Docker Setup Validation Script
# Created: 2025-10-24

set -e

echo "=========================================="
echo "Manus Docker Setup Validation"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check function
check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "${RED}✗${NC} $1"
        return 1
    fi
}

# Warning function
warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo "1. Checking required files..."
echo "----------------------------"

test -f docker-compose.yml && check "docker-compose.yml exists" || check "docker-compose.yml exists"
test -f Dockerfile && check "Dockerfile exists" || check "Dockerfile exists"
test -f .env && check ".env exists" || check ".env exists"
test -f .dockerignore && check ".dockerignore exists" || check ".dockerignore exists"
test -f requirements-full.txt && check "requirements-full.txt exists" || check "requirements-full.txt exists"
test -f api/main.py && check "api/main.py exists" || check "api/main.py exists"
test -f docker/init-db.sql && check "docker/init-db.sql exists" || check "docker/init-db.sql exists"

echo ""
echo "2. Checking required directories..."
echo "-----------------------------------"

test -d workspace && check "workspace/ directory exists" || check "workspace/ directory exists"
test -d workspace/loot && check "workspace/loot/ directory exists" || check "workspace/loot/ directory exists"
test -d logs && check "logs/ directory exists" || check "logs/ directory exists"
test -d data && check "data/ directory exists" || check "data/ directory exists"
test -d reports && check "reports/ directory exists" || check "reports/ directory exists"
test -d config && check "config/ directory exists" || check "config/ directory exists"

echo ""
echo "3. Validating file syntax..."
echo "----------------------------"

# Validate YAML
python3.11 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))" 2>/dev/null && \
    check "docker-compose.yml YAML syntax valid" || \
    check "docker-compose.yml YAML syntax valid"

# Validate Python
python3.11 -c "import ast; ast.parse(open('api/main.py').read())" 2>/dev/null && \
    check "api/main.py Python syntax valid" || \
    check "api/main.py Python syntax valid"

echo ""
echo "4. Checking environment variables..."
echo "------------------------------------"

grep -q "POSTGRES_PASSWORD" .env && check "POSTGRES_PASSWORD is set" || check "POSTGRES_PASSWORD is set"
grep -q "POSTGRES_DB" .env && check "POSTGRES_DB is set" || check "POSTGRES_DB is set"
grep -q "SECRET_KEY" .env && check "SECRET_KEY is set" || check "SECRET_KEY is set"
grep -q "OLLAMA_HOST" .env && check "OLLAMA_HOST is set" || check "OLLAMA_HOST is set"

echo ""
echo "5. Checking Docker availability..."
echo "----------------------------------"

if command -v docker &> /dev/null; then
    check "Docker is installed"
    
    if docker ps &> /dev/null; then
        check "Docker daemon is running"
    else
        warn "Docker daemon is not running or permission denied"
        echo "  Run: sudo service docker start"
        echo "  Or: sudo usermod -aG docker \$USER && newgrp docker"
    fi
else
    warn "Docker is not installed"
    echo "  Please install Docker first"
fi

if command -v docker-compose &> /dev/null || docker compose version &> /dev/null 2>&1; then
    check "Docker Compose is available"
else
    warn "Docker Compose is not installed"
    echo "  Please install Docker Compose"
fi

echo ""
echo "6. Checking file permissions..."
echo "-------------------------------"

test -r docker-compose.yml && check "docker-compose.yml is readable" || check "docker-compose.yml is readable"
test -r Dockerfile && check "Dockerfile is readable" || check "Dockerfile is readable"
test -w workspace && check "workspace/ is writable" || check "workspace/ is writable"
test -w logs && check "logs/ is writable" || check "logs/ is writable"

echo ""
echo "7. Checking repository links..."
echo "-------------------------------"

if grep -q "donlasahachat1-sys/manus" README.md; then
    check "README.md has correct repository link"
else
    warn "README.md may have incorrect repository link"
fi

if grep -q "donlasahachat1-sys/manus" DEPLOYMENT_GUIDE.md; then
    check "DEPLOYMENT_GUIDE.md has correct repository link"
else
    warn "DEPLOYMENT_GUIDE.md may have incorrect repository link"
fi

echo ""
echo "=========================================="
echo "Validation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. If Docker is not running: sudo service docker start"
echo "2. Build images: docker compose build --no-cache"
echo "3. Start services: docker compose up -d"
echo "4. Check logs: docker compose logs -f"
echo "5. Pull LLM models: docker exec -it manus-ollama ollama pull mixtral:latest"
echo ""

