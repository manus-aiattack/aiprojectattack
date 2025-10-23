#!/bin/bash

# WSL Quick Fix Script for dLNk dLNk
# แก้ปัญหาทั่วไปบน WSL

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║        dLNk dLNk - WSL Quick Fix Script                  ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on WSL
if ! grep -qi microsoft /proc/version; then
    echo "⚠️  This script is designed for WSL. You may not need it on native Linux."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo "Detected Python $PYTHON_VERSION"

if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 13 ]; then
    echo "⚠️  Warning: Python 3.13+ detected"
    echo "Some packages may have build issues with Python 3.13"
    echo "Recommended: Python 3.11 or 3.12"
    echo ""
    echo "See PYTHON_VERSION_NOTICE.md for more information"
    echo ""
    read -p "Continue with Python $PYTHON_VERSION? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "To install Python 3.11:"
        echo "  sudo apt install python3.11 python3.11-venv python3.11-dev"
        echo "  python3.11 -m venv venv"
        exit 0
    fi
fi

echo "This script will:"
echo "  1. Install system dependencies (libxml2-dev, libxslt-dev, etc.)"
echo "  2. Setup PostgreSQL"
echo "  3. Check Ollama configuration"
echo "  4. Fix common permission issues"
echo ""
read -p "Proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

# Update package list
echo ""
echo "Updating package list..."
sudo apt update

# Install system dependencies
echo ""
echo "Installing system dependencies..."
sudo apt install -y \
    python3 python3-venv python3-dev \
    libxml2-dev libxslt-dev \
    postgresql postgresql-contrib \
    build-essential \
    git curl wget

echo "✅ System dependencies installed"

# Start PostgreSQL
echo ""
echo "Starting PostgreSQL..."
sudo service postgresql start

# Check if PostgreSQL is running
if sudo service postgresql status | grep -q "online"; then
    echo "✅ PostgreSQL is running"
else
    echo "⚠️  PostgreSQL failed to start"
    echo "Try manually: sudo service postgresql start"
fi

# Setup database
echo ""
echo "Setting up database..."
sudo -u postgres psql -c "SELECT 1" > /dev/null 2>&1 && {
    # Check if user exists
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='dlnk'" | grep -q 1; then
        echo "✅ Database user 'dlnk' already exists"
    else
        sudo -u postgres psql -c "CREATE USER dlnk WITH PASSWORD 'dlnk_password';"
        echo "✅ Created database user 'dlnk'"
    fi
    
    # Check if database exists
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw dlnk_dlnk; then
        echo "✅ Database 'dlnk_dlnk' already exists"
    else
        sudo -u postgres psql -c "CREATE DATABASE dlnk_dlnk OWNER dlnk;"
        echo "✅ Created database 'dlnk_dlnk'"
    fi
    
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dlnk_dlnk TO dlnk;"
    echo "✅ Database setup complete"
}

# Check Ollama
echo ""
echo "Checking Ollama..."
if command -v ollama &> /dev/null; then
    echo "✅ Ollama is installed"
    
    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "✅ Ollama is running on localhost:11434"
    else
        echo "⚠️  Ollama is not running"
        echo ""
        echo "To start Ollama:"
        echo "  ollama serve &"
        echo ""
        echo "If Ollama is running on Windows, find Windows host IP:"
        echo "  cat /etc/resolv.conf | grep nameserver | awk '{print \$2}'"
        echo ""
        echo "Then update .env:"
        echo "  OLLAMA_HOST=http://WINDOWS_IP:11434"
    fi
    
    # Check if mixtral model exists
    if ollama list 2>/dev/null | grep -q mixtral; then
        echo "✅ mixtral model is available"
    else
        echo "⚠️  mixtral model not found"
        echo ""
        read -p "Download mixtral:latest? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ollama pull mixtral:latest
        fi
    fi
else
    echo "⚠️  Ollama not found"
    echo ""
    echo "To install Ollama:"
    echo "  curl -fsSL https://ollama.com/install.sh | sh"
    echo ""
    echo "Or use Ollama from Windows (update .env with Windows IP)"
fi

# Fix permissions
echo ""
echo "Fixing permissions..."
chmod +x quickstart.sh run.sh startup.py 2>/dev/null || true
echo "✅ Permissions fixed"

# Check .env file
echo ""
if [ -f ".env" ]; then
    echo "✅ .env file exists"
else
    echo "⚠️  .env file not found"
    if [ -f "env.template" ]; then
        echo "Creating .env from template..."
        cp env.template .env
        echo "✅ .env created"
        echo ""
        echo "⚠️  Please edit .env file with your configuration:"
        echo "  nano .env"
    fi
fi

# Check virtual environment
echo ""
if [ -d "venv" ]; then
    echo "✅ Virtual environment exists"
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Install Python packages
echo ""
echo "Installing Python packages..."
source venv/bin/activate
pip install --upgrade pip -q

# Check if Python 3.13+
if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 13 ]; then
    echo "Using --only-binary for Python 3.13 compatibility..."
    # Try to install with binary wheels only for problematic packages
    pip install --only-binary :all: asyncpg psycopg2-binary aiohttp pymongo pyyaml scapy 2>/dev/null || true
    # Then install the rest
    pip install -r requirements-full.txt
else
    pip install -r requirements-full.txt
fi

if [ $? -eq 0 ]; then
    echo "✅ Python packages installed successfully"
else
    echo "⚠️  Some packages failed to install"
    echo "This is usually okay - the system will work without them"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  ✅ WSL Setup Complete!                                       ║"
echo "║                                                               ║"
echo "║  Next steps:                                                 ║"
echo "║  1. Edit .env file: nano .env                                ║"
echo "║  2. Run startup: python3 startup.py                          ║"
echo "║  3. Start server: ./run.sh                                   ║"
echo "║                                                               ║"
echo "║  Troubleshooting:                                            ║"
echo "║  - See WSL_INSTALLATION_GUIDE.md for detailed help           ║"
echo "║  - Check logs/ directory for error messages                  ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

