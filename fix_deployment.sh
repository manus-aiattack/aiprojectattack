#!/usr/bin/env bash
# Fix deployment issues

set -e

echo "========================================================"
echo "Fixing dLNk Deployment Issues"
echo "========================================================"
echo ""

# Fix 1: Upgrade pydantic
echo "[FIX 1] Upgrading pydantic to fix dependency conflict..."
pip3 install --upgrade pydantic pydantic-settings --quiet
echo "✓ Pydantic upgraded"
echo ""

# Fix 2: Regenerate .env file with C2_DOMAIN
echo "[FIX 2] Updating .env file with C2_DOMAIN..."
if [ -f ".env" ]; then
    # Check if C2_DOMAIN exists
    if ! grep -q "^C2_DOMAIN=" .env; then
        echo "C2_DOMAIN=localhost:8000" >> .env
        echo "✓ Added C2_DOMAIN to .env"
    else
        echo "✓ C2_DOMAIN already exists in .env"
    fi
else
    # Create new .env from template
    cp .env.template .env
    echo "✓ Created .env from template (with C2_DOMAIN)"
fi
echo ""

# Fix 3: Initialize database
echo "[FIX 3] Initializing database..."
export PYTHONPATH="$(pwd):$PYTHONPATH"
python3 startup.py
echo ""

echo "========================================================"
echo "Fixes Applied Successfully!"
echo "========================================================"
echo ""
echo "You can now start the server with:"
echo "  ./start_server.sh"
echo ""

