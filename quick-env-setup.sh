#!/bin/bash

# Manus Attack Platform - Quick Environment Setup
# This script creates the .env file needed for Docker deployment
# Created: 2025-10-24

set -e

echo "=========================================="
echo "Manus Quick Environment Setup"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env already exists
if [ -f .env ]; then
    echo -e "${YELLOW}Warning: .env file already exists!${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled. Existing .env file preserved."
        exit 0
    fi
    echo "Backing up existing .env to .env.backup..."
    cp .env .env.backup
fi

# Check if .env.docker template exists
if [ ! -f .env.docker ]; then
    echo "Error: .env.docker template not found!"
    echo "Please make sure you're in the manus directory."
    exit 1
fi

# Copy template to .env
echo "Creating .env file from template..."
cp .env.docker .env

echo -e "${GREEN}✓${NC} .env file created successfully!"
echo ""

# Ask if user wants to customize important values
echo "Do you want to customize security settings now? (recommended for production)"
read -p "Customize now? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Generating secure SECRET_KEY..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    
    # Update SECRET_KEY in .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    else
        # Linux
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    fi
    
    echo -e "${GREEN}✓${NC} Generated and set new SECRET_KEY"
    echo ""
    
    # Ask for database password
    echo "Current POSTGRES_PASSWORD is: postgres"
    read -p "Enter new database password (or press Enter to keep 'postgres'): " DB_PASSWORD
    
    if [ ! -z "$DB_PASSWORD" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASSWORD/" .env
            sed -i '' "s|postgresql://postgres:postgres@|postgresql://postgres:$DB_PASSWORD@|" .env
        else
            sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASSWORD/" .env
            sed -i "s|postgresql://postgres:postgres@|postgresql://postgres:$DB_PASSWORD@|" .env
        fi
        echo -e "${GREEN}✓${NC} Updated database password"
    else
        echo "Keeping default database password"
    fi
    
    echo ""
    # Ask for simulation mode
    echo "SIMULATION_MODE determines if attacks are real or simulated"
    echo "  True  = Safe testing mode (recommended for learning)"
    echo "  False = Live attack mode (use only with authorization!)"
    read -p "Enable simulation mode? (Y/n): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/SIMULATION_MODE=.*/SIMULATION_MODE=True/" .env
        else
            sed -i "s/SIMULATION_MODE=.*/SIMULATION_MODE=True/" .env
        fi
        echo -e "${GREEN}✓${NC} Enabled simulation mode"
    else
        echo -e "${YELLOW}⚠${NC} Simulation mode disabled - USE WITH CAUTION!"
    fi
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Your .env file is ready. Next steps:"
echo ""
echo "1. Review your .env file:"
echo "   nano .env"
echo ""
echo "2. Validate Docker setup:"
echo "   ./validate-docker-setup.sh"
echo ""
echo "3. Build and start services:"
echo "   docker compose build --no-cache"
echo "   docker compose up -d"
echo ""
echo "4. Check logs:"
echo "   docker compose logs -f"
echo ""
echo "For detailed instructions, see:"
echo "  - ENV_SETUP_GUIDE.md"
echo "  - DOCKER_DEPLOYMENT.md"
echo ""

