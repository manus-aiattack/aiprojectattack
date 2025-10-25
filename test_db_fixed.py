"""
Fixed Database Connection Test
Uses environment variables instead of hardcoded values
"""
import asyncio
import asyncpg
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config.env_loader import get_env, get_env_int, get_database_url


async def test_connection():
    """Test database connection using environment variables"""
    
    # Get database configuration from environment
    db_host = get_env('DB_HOST', 'localhost')
    db_port = get_env_int('DB_PORT', 5432)
    db_user = get_env('DB_USER', 'dlnk')
    db_password = get_env('DB_PASSWORD', '')
    db_name = get_env('DB_NAME', 'dlnk_db')
    
    print("=" * 60)
    print("Database Connection Test")
    print("=" * 60)
    print(f"Host: {db_host}")
    print(f"Port: {db_port}")
    print(f"User: {db_user}")
    print(f"Database: {db_name}")
    print(f"Password: {'***' if db_password else 'NOT SET'}")
    print("=" * 60)
    
    # Try using DATABASE_URL first
    database_url = get_env('DATABASE_URL')
    if database_url:
        print(f"\nUsing DATABASE_URL: {database_url[:30]}...")
        try:
            conn = await asyncpg.connect(dsn=database_url)
            print("✅ Connected using DATABASE_URL!")
            result = await conn.fetchval("SELECT version()")
            print(f"✅ PostgreSQL Version: {result}")
            await conn.close()
            return True
        except Exception as e:
            print(f"❌ Failed to connect using DATABASE_URL: {e}")
    
    # Try using individual parameters
    print(f"\nTrying connection with individual parameters...")
    try:
        if db_password:
            conn = await asyncpg.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_password,
                database=db_name
            )
        else:
            conn = await asyncpg.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                database=db_name
            )
        
        print("✅ Connected!")
        result = await conn.fetchval("SELECT version()")
        print(f"✅ PostgreSQL Version: {result}")
        
        # Test a simple query
        result = await conn.fetchval("SELECT 1 + 1")
        print(f"✅ Test query result: {result}")
        
        await conn.close()
        print("\n✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        print(f"Error type: {type(e).__name__}")
        print("\nTroubleshooting:")
        print("1. Check if PostgreSQL is running")
        print("2. Verify database credentials in .env file")
        print("3. Ensure database exists: createdb dlnk_db")
        print("4. Check PostgreSQL authentication settings (pg_hba.conf)")
        return False


def main():
    """Main function"""
    result = asyncio.run(test_connection())
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()

