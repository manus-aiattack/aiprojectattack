"""
Database Service - PostgreSQL with asyncpg
"""

import asyncpg
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.logger import log


class Database:
    """Database service for PostgreSQL"""
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        # Build DATABASE_URL from individual components if not set
        dsn = os.getenv("DATABASE_URL")
        if not dsn:
            db_host = os.getenv("DB_HOST", "localhost")
            db_port = os.getenv("DB_PORT", "5432")
            db_user = os.getenv("DB_USER", "dlnk_user")
            db_password = os.getenv("DB_PASSWORD", "")
            db_name = os.getenv("DB_NAME", "dlnk")
            dsn = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        self.dsn = dsn
    
    async def connect(self):
        """Connect to database"""
        try:
            self.pool = await asyncpg.create_pool(
                self.dsn,
                min_size=5,
                max_size=20,
                command_timeout=60
            )
            log.success("[Database] Connected to PostgreSQL")
            
            # Initialize schema
            await self._init_schema()
            
        except Exception as e:
            log.error(f"[Database] Connection failed: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from database"""
        if self.pool:
            await self.pool.close()
            log.info("[Database] Disconnected")
    
    async def health_check(self) -> bool:
        """Check database health"""
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return True
        except:
            return False
    
    async def _init_schema(self):
        """Initialize database schema"""
        schema = """
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user')),
            api_key VARCHAR(64) UNIQUE NOT NULL,
            quota_limit INTEGER DEFAULT 100,
            quota_used INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW(),
            last_login TIMESTAMP,
            metadata JSONB DEFAULT '{}'::jsonb
        );
        
        -- Attacks table
        CREATE TABLE IF NOT EXISTS attacks (
            id SERIAL PRIMARY KEY,
            attack_id VARCHAR(64) UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            target_url TEXT NOT NULL,
            attack_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'stopped')),
            started_at TIMESTAMP DEFAULT NOW(),
            completed_at TIMESTAMP,
            results JSONB DEFAULT '{}'::jsonb,
            error_message TEXT,
            metadata JSONB DEFAULT '{}'::jsonb
        );
        
        -- Agent logs table
        CREATE TABLE IF NOT EXISTS agent_logs (
            id SERIAL PRIMARY KEY,
            attack_id VARCHAR(64) REFERENCES attacks(attack_id) ON DELETE CASCADE,
            agent_name VARCHAR(100) NOT NULL,
            action TEXT NOT NULL,
            status VARCHAR(20) NOT NULL,
            output TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'::jsonb
        );
        
        -- Dumped files table
        CREATE TABLE IF NOT EXISTS dumped_files (
            id SERIAL PRIMARY KEY,
            attack_id VARCHAR(64) REFERENCES attacks(attack_id) ON DELETE CASCADE,
            file_name VARCHAR(255) NOT NULL,
            file_path TEXT NOT NULL,
            file_size BIGINT,
            file_type VARCHAR(50),
            file_hash VARCHAR(64),
            created_at TIMESTAMP DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'::jsonb
        );
        
        -- System logs table
        CREATE TABLE IF NOT EXISTS system_logs (
            id SERIAL PRIMARY KEY,
            log_level VARCHAR(20) NOT NULL,
            component VARCHAR(100) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'::jsonb
        );
        
        -- Create indexes
        CREATE INDEX IF NOT EXISTS idx_attacks_user_id ON attacks(user_id);
        CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
        CREATE INDEX IF NOT EXISTS idx_attacks_started_at ON attacks(started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_agent_logs_attack_id ON agent_logs(attack_id);
        CREATE INDEX IF NOT EXISTS idx_agent_logs_created_at ON agent_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_dumped_files_attack_id ON dumped_files(attack_id);
        CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at DESC);
        """
        
        async with self.pool.acquire() as conn:
            await conn.execute(schema)
        
        log.success("[Database] Schema initialized")
        
        # Create default admin user if not exists
        await self._create_default_admin()
    
    async def _create_default_admin(self):
        """Create default admin user"""
        import secrets
        
        admin_key = os.getenv("ADMIN_API_KEY", secrets.token_urlsafe(32))
        
        async with self.pool.acquire() as conn:
            exists = await conn.fetchval(
                "SELECT 1 FROM users WHERE username = $1",
                "admin"
            )
            
            if not exists:
                await conn.execute("""
                    INSERT INTO users (username, role, api_key, quota_limit, is_active)
                    VALUES ($1, $2, $3, $4, $5)
                """, "admin", "admin", admin_key, 999999, True)
                
                log.success(f"[Database] Default admin created with API Key: {admin_key}")
                
                # Save to file
                workspace_dir = os.getenv('WORKSPACE_DIR', 'workspace')
                admin_key_path = os.path.join(workspace_dir, 'ADMIN_KEY.txt')
                os.makedirs(workspace_dir, exist_ok=True)
                with open(admin_key_path, "w") as f:
                    f.write(f"Admin API Key: {admin_key}\n")
                    f.write(f"Created at: {datetime.now().isoformat()}\n")
    
    # User operations
    async def create_user(self, username: str, role: str, api_key: str, quota_limit: int = 100) -> int:
        """Create new user"""
        async with self.pool.acquire() as conn:
            user_id = await conn.fetchval("""
                INSERT INTO users (username, role, api_key, quota_limit)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, username, role, api_key, quota_limit)
            return user_id
    
    async def get_user_by_key(self, api_key: str) -> Optional[Dict]:
        """Get user by API key"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, username, role, api_key, quota_limit, quota_used, is_active, created_at, last_login
                FROM users
                WHERE api_key = $1
            """, api_key)
            
            if row:
                return dict(row)
            return None
    
    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, username, role, api_key, quota_limit, quota_used, is_active, created_at, last_login
                FROM users
                WHERE id = $1
            """, user_id)
            
            if row:
                return dict(row)
            return None
    
    async def update_last_login(self, user_id: int):
        """Update last login time"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE users
                SET last_login = NOW()
                WHERE id = $1
            """, user_id)
    
    async def update_quota(self, user_id: int, increment: int = 1):
        """Update user quota"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE users
                SET quota_used = quota_used + $2
                WHERE id = $1
            """, user_id, increment)
    
    async def get_all_users(self) -> List[Dict]:
        """Get all users (admin only)"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, username, role, quota_limit, quota_used, is_active, created_at, last_login
                FROM users
                ORDER BY created_at DESC
            """)
            return [dict(row) for row in rows]
    
    async def delete_user(self, user_id: int):
        """Delete user"""
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)
    
    async def toggle_user_status(self, user_id: int, is_active: bool):
        """Toggle user active status"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE users
                SET is_active = $2
                WHERE id = $1
            """, user_id, is_active)
    
    # Attack operations
    async def create_attack(self, attack_id: str, user_id: int, target_url: str, attack_type: str) -> int:
        """Create new attack"""
        async with self.pool.acquire() as conn:
            attack_pk = await conn.fetchval("""
                INSERT INTO attacks (attack_id, user_id, target_url, attack_type, status)
                VALUES ($1, $2, $3, $4, 'pending')
                RETURNING id
            """, attack_id, user_id, target_url, attack_type)
            return attack_pk
    
    async def get_attack(self, attack_id: str) -> Optional[Dict]:
        """Get attack by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT a.*, u.username
                FROM attacks a
                JOIN users u ON a.user_id = u.id
                WHERE a.attack_id = $1
            """, attack_id)
            
            if row:
                return dict(row)
            return None
    
    async def update_attack_status(self, attack_id: str, status: str, results: Optional[Dict] = None, error: Optional[str] = None):
        """Update attack status"""
        async with self.pool.acquire() as conn:
            if status in ['success', 'failed', 'stopped']:
                await conn.execute("""
                    UPDATE attacks
                    SET status = $2, results = $3, error_message = $4, completed_at = NOW()
                    WHERE attack_id = $1
                """, attack_id, status, results or {}, error)
            else:
                await conn.execute("""
                    UPDATE attacks
                    SET status = $2
                    WHERE attack_id = $1
                """, attack_id, status)
    
    async def get_user_attacks(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get user's attacks"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT attack_id, target_url, attack_type, status, started_at, completed_at
                FROM attacks
                WHERE user_id = $1
                ORDER BY started_at DESC
                LIMIT $2
            """, user_id, limit)
            return [dict(row) for row in rows]
    
    async def get_all_attacks(self, limit: int = 100) -> List[Dict]:
        """Get all attacks (admin only)"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT a.attack_id, a.target_url, a.attack_type, a.status, a.started_at, a.completed_at, u.username
                FROM attacks a
                JOIN users u ON a.user_id = u.id
                ORDER BY a.started_at DESC
                LIMIT $1
            """, limit)
            return [dict(row) for row in rows]
    
    async def get_active_attacks_count(self) -> int:
        """Get count of active attacks"""
        async with self.pool.acquire() as conn:
            count = await conn.fetchval("""
                SELECT COUNT(*)
                FROM attacks
                WHERE status IN ('pending', 'running')
            """)
            return count
    
    # Agent log operations
    async def add_agent_log(self, attack_id: str, agent_name: str, action: str, status: str, output: Optional[str] = None):
        """Add agent log"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO agent_logs (attack_id, agent_name, action, status, output)
                VALUES ($1, $2, $3, $4, $5)
            """, attack_id, agent_name, action, status, output)
    
    async def get_attack_logs(self, attack_id: str) -> List[Dict]:
        """Get logs for an attack"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT agent_name, action, status, output, created_at
                FROM agent_logs
                WHERE attack_id = $1
                ORDER BY created_at ASC
            """, attack_id)
            return [dict(row) for row in rows]
    
    async def get_all_agent_logs(self, limit: int = 500) -> List[Dict]:
        """Get all agent logs (admin only)"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT attack_id, agent_name, action, status, output, created_at
                FROM agent_logs
                ORDER BY created_at DESC
                LIMIT $1
            """, limit)
            return [dict(row) for row in rows]
    
    # File operations
    async def add_dumped_file(self, attack_id: str, file_name: str, file_path: str, file_size: int, file_type: str, file_hash: str):
        """Add dumped file record"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO dumped_files (attack_id, file_name, file_path, file_size, file_type, file_hash)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, attack_id, file_name, file_path, file_size, file_type, file_hash)
    
    async def get_attack_files(self, attack_id: str) -> List[Dict]:
        """Get files for an attack"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, file_name, file_path, file_size, file_type, file_hash, created_at
                FROM dumped_files
                WHERE attack_id = $1
                ORDER BY created_at DESC
            """, attack_id)
            return [dict(row) for row in rows]
    
    async def get_file_by_id(self, file_id: int) -> Optional[Dict]:
        """Get file by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT df.*, a.user_id
                FROM dumped_files df
                JOIN attacks a ON df.attack_id = a.attack_id
                WHERE df.id = $1
            """, file_id)
            
            if row:
                return dict(row)
            return None
    
    # System log operations
    async def add_system_log(self, log_level: str, component: str, message: str, metadata: Optional[Dict] = None):
        """Add system log"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO system_logs (log_level, component, message, metadata)
                VALUES ($1, $2, $3, $4)
            """, log_level, component, message, metadata or {})
    
    async def get_system_logs(self, limit: int = 500) -> List[Dict]:
        """Get system logs (admin only)"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT log_level, component, message, created_at, metadata
                FROM system_logs
                ORDER BY created_at DESC
                LIMIT $1
            """, limit)
            return [dict(row) for row in rows]

