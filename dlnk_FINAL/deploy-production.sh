#!/bin/bash
# dLNk Attack Platform - Production Deployment Script
# This script prepares and deploys the system for production use

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check available disk space (minimum 10GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 10485760 ]; then
        warning "Low disk space. At least 10GB recommended for production deployment."
    fi
    
    success "System requirements check passed"
}

# Generate secure secrets
generate_secrets() {
    log "Generating secure secrets..."
    
    # Generate SECRET_KEY
    if [ ! -f .env.production ]; then
        SECRET_KEY=$(openssl rand -base64 64 | tr -d '\n')
        DB_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
        REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
        
        cat > .env.production << EOF
# Generated secrets - DO NOT COMMIT TO VERSION CONTROL
SECRET_KEY=${SECRET_KEY}
DB_PASSWORD=${DB_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}

# Add your other production environment variables here
# Copy from .env.production.template and customize
EOF
        
        success "Generated .env.production with secure secrets"
        warning "Please review and customize .env.production before deployment"
    else
        warning ".env.production already exists, skipping secret generation"
    fi
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    mkdir -p workspace/loot/exfiltrated
    mkdir -p logs
    mkdir -p data
    mkdir -p reports
    mkdir -p scripts
    
    # Set proper permissions
    chmod 755 workspace logs data reports scripts
    chmod 700 workspace/loot
    
    success "Directories created with proper permissions"
}

# Create database initialization script
create_db_init() {
    log "Creating database initialization script..."
    
    cat > scripts/init-db.sql << 'EOF'
-- dLNk Attack Platform Database Initialization
-- This script runs when the PostgreSQL container starts for the first time

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create additional schemas if needed
-- CREATE SCHEMA IF NOT EXISTS audit;
-- CREATE SCHEMA IF NOT EXISTS logs;

-- Set up row level security (RLS) for sensitive tables
-- This will be implemented in the main schema.sql

-- Create backup user with limited privileges
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'dlnk_backup') THEN
        CREATE ROLE dlnk_backup WITH LOGIN PASSWORD 'backup_password_change_this';
        GRANT CONNECT ON DATABASE dlnk_production TO dlnk_backup;
        GRANT USAGE ON SCHEMA public TO dlnk_backup;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO dlnk_backup;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO dlnk_backup;
    END IF;
END
$$;

-- Log initialization
INSERT INTO system_logs (level, message, created_at) 
VALUES ('INFO', 'Database initialized successfully', NOW())
ON CONFLICT DO NOTHING;
EOF
    
    success "Database initialization script created"
}

# Build and start services
deploy_services() {
    log "Building and starting services..."
    
    # Build the application image
    docker-compose build --no-cache
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be healthy
    log "Waiting for services to be healthy..."
    sleep 30
    
    # Check service health
    if docker-compose ps | grep -q "unhealthy"; then
        error "Some services are unhealthy. Check logs with: docker-compose logs"
        exit 1
    fi
    
    success "All services are running and healthy"
}

# Run security checks
security_checks() {
    log "Running security checks..."
    
    # Check for default passwords
    if grep -q "CHANGE_THIS" .env.production 2>/dev/null; then
        warning "Default passwords detected in .env.production. Please change them."
    fi
    
    # Check file permissions
    if [ -f .env.production ] && [ $(stat -c %a .env.production) != "600" ]; then
        warning "Setting secure permissions for .env.production"
        chmod 600 .env.production
    fi
    
    # Check Docker security
    if docker info 2>/dev/null | grep -q "Root Dir: /var/lib/docker"; then
        warning "Docker is running as root. Consider using rootless Docker for production."
    fi
    
    success "Security checks completed"
}

# Create backup script
create_backup_script() {
    log "Creating backup script..."
    
    cat > scripts/backup.sh << 'EOF'
#!/bin/bash
# dLNk Attack Platform - Backup Script

set -euo pipefail

BACKUP_DIR="/opt/dlnk/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="dlnk_backup_${DATE}.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
docker-compose exec -T db pg_dump -U dlnk_user dlnk_production > "$BACKUP_DIR/db_backup_${DATE}.sql"

# File system backup
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude='workspace/loot/exfiltrated' \
    --exclude='logs/*.log' \
    --exclude='.git' \
    workspace data reports config

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "dlnk_backup_*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "db_backup_*.sql" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
EOF
    
    chmod +x scripts/backup.sh
    success "Backup script created"
}

# Create monitoring script
create_monitoring_script() {
    log "Creating monitoring script..."
    
    cat > scripts/monitor.sh << 'EOF'
#!/bin/bash
# dLNk Attack Platform - Monitoring Script

# Check service health
check_services() {
    echo "=== Service Health Check ==="
    docker-compose ps
    echo ""
}

# Check resource usage
check_resources() {
    echo "=== Resource Usage ==="
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
    echo ""
}

# Check logs for errors
check_logs() {
    echo "=== Recent Errors ==="
    docker-compose logs --tail=50 | grep -i error || echo "No recent errors found"
    echo ""
}

# Main monitoring function
main() {
    check_services
    check_resources
    check_logs
}

main "$@"
EOF
    
    chmod +x scripts/monitor.sh
    success "Monitoring script created"
}

# Main deployment function
main() {
    log "Starting dLNk Attack Platform Production Deployment"
    
    check_root
    check_requirements
    generate_secrets
    create_directories
    create_db_init
    create_backup_script
    create_monitoring_script
    security_checks
    deploy_services
    
    success "Production deployment completed successfully!"
    
    echo ""
    echo "Next steps:"
    echo "1. Review and customize .env.production"
    echo "2. Access the API at: http://localhost:8000"
    echo "3. Check API documentation at: http://localhost:8000/docs"
    echo "4. Monitor services with: ./scripts/monitor.sh"
    echo "5. Set up automated backups with: ./scripts/backup.sh"
    echo ""
    echo "Security reminders:"
    echo "- Change all default passwords in .env.production"
    echo "- Configure firewall rules"
    echo "- Set up SSL/TLS certificates"
    echo "- Enable log monitoring and alerting"
    echo "- Regular security updates"
}

# Run main function
main "$@"
