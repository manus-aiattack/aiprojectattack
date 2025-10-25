#!/bin/bash

# dLNk - Fix PostgreSQL Authentication Script

set -e

echo "🔧 Fixing PostgreSQL Authentication..."
echo "======================================"
echo ""

# Stop and remove old container
echo "1. Removing old PostgreSQL container..."
docker stop dlnk_postgres 2>/dev/null || true
docker rm dlnk_postgres 2>/dev/null || true
echo "✅ Old container removed"
echo ""

# Create new container with trust authentication
echo "2. Creating new PostgreSQL container with trust authentication..."
docker run -d --name dlnk_postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 \
  postgres:15

echo "✅ Container created"
echo ""

# Wait for PostgreSQL to be ready
echo "3. Waiting for PostgreSQL to be ready (30 seconds)..."
sleep 30

# Check if ready
docker exec dlnk_postgres pg_isready -U dlnk
echo "✅ PostgreSQL is ready"
echo ""

# Create database schema
echo "4. Creating database schema..."
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db << 'EOSQL'
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    role VARCHAR NOT NULL,
    quota_limit INTEGER DEFAULT 100,
    quota_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR PRIMARY KEY,
    key VARCHAR UNIQUE NOT NULL,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attacks (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    target_url VARCHAR NOT NULL,
    attack_type VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Create admin user
INSERT INTO users (id, username, role, quota_limit, quota_used, created_at)
VALUES (
    'admin-001',
    'admin',
    'admin',
    999999,
    0,
    CURRENT_TIMESTAMP
)
ON CONFLICT (username) DO NOTHING;

-- Create admin API key
INSERT INTO api_keys (id, key, user_id, created_at)
VALUES (
    'key-001',
    'dlnk_admin_key_12345678901234567890',
    'admin-001',
    CURRENT_TIMESTAMP
)
ON CONFLICT (key) DO NOTHING;

-- Show tables
\dt

-- Show admin user and key
SELECT 
    u.username,
    u.role,
    u.quota_limit,
    k.key as api_key
FROM users u
JOIN api_keys k ON k.user_id = u.id
WHERE u.username = 'admin';
EOSQL

echo "✅ Database schema created"
echo ""

# Update .env file
echo "5. Updating .env file..."
cd /mnt/c/projecattack/Manus/dlnk_FINAL

cat > .env << 'EOF'
DATABASE_URL=postgresql://dlnk@localhost:5432/dlnk_db
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
WORKSPACE_DIR=/tmp/dlnk_workspace
LOOT_DIR=/tmp/dlnk_loot
API_HOST=0.0.0.0
API_PORT=8000
NOTIFICATION_CHANNELS=console
EOF

echo "✅ .env file updated"
echo ""

# Update database.py default DSN
echo "6. Updating api/services/database.py..."
sed -i 's|postgresql://dlnk:.*@localhost:5432/.*"|postgresql://dlnk@localhost:5432/dlnk_db"|g' api/services/database.py
echo "✅ database.py updated"
echo ""

# Export environment variables
echo "7. Exporting environment variables..."
export DATABASE_URL=postgresql://dlnk@localhost:5432/dlnk_db
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=mixtral:latest
export WORKSPACE_DIR=/tmp/dlnk_workspace
export LOOT_DIR=/tmp/dlnk_loot
export API_HOST=0.0.0.0
export API_PORT=8000
export NOTIFICATION_CHANNELS=console
echo "✅ Environment variables exported"
echo ""

echo "✅ PostgreSQL authentication fixed!"
echo ""
echo "📝 Admin API Key: dlnk_admin_key_12345678901234567890"
echo ""
echo "Next steps:"
echo "  1. cd /mnt/c/projecattack/Manus/dlnk_FINAL"
echo "  2. source venv/bin/activate"
echo "  3. python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload"
echo ""

