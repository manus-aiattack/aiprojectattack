#!/bin/bash

# dLNk Quick Install Script for Ubuntu 24.04
# Handles virtual environment automatically

set -e

echo "🚀 dLNk Attack Platform - Quick Install"
echo "========================================"
echo ""

# Check if Python 3.11 is available
if ! command -v python3.11 &> /dev/null; then
    echo "📦 Installing Python 3.11..."
    sudo apt update
    sudo apt install -y python3.11 python3.11-venv python3.11-dev
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3.11 -m venv venv
fi

# Activate virtual environment
echo "✅ Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements-production.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Create .env file:"
echo "   cp env.template .env"
echo ""
echo "3. Run the server:"
echo "   python startup.py"
echo ""
echo "   OR"
echo ""
echo "   uvicorn api.main_api:app --host 0.0.0.0 --port 8000"
echo ""
echo "4. Access the system:"
echo "   http://localhost:8000"
echo "   http://localhost:8000/docs"
echo ""

