#!/usr/bin/env python3
"""
Test Configuration Script
Tests all configuration settings before initializing database
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 80)
print("dLNk Attack Platform - Configuration Test")
print("=" * 80)
print()

# Test 1: Check if .env file exists
print("📄 Checking .env file...")
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    print(f"✅ .env file found at: {env_file}")
else:
    print(f"❌ .env file NOT found at: {env_file}")
    print("   Please create .env file first!")
    sys.exit(1)

print()

# Test 2: Try to import python-dotenv
print("📦 Checking python-dotenv...")
try:
    from dotenv import load_dotenv
    print("✅ python-dotenv installed")
except ImportError:
    print("❌ python-dotenv NOT installed")
    print("   Run: pip install python-dotenv")
    sys.exit(1)

print()

# Test 3: Load .env file
print("🔧 Loading .env file...")
load_dotenv()
print("✅ .env file loaded")
print()

# Test 4: Check database settings
print("🗄️  Checking database settings...")
import os

db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_NAME")

print(f"  DB_HOST: {db_host or '❌ NOT SET'}")
print(f"  DB_PORT: {db_port or '❌ NOT SET'}")
print(f"  DB_USER: {db_user or '❌ NOT SET'}")
print(f"  DB_PASSWORD: {'***' if db_password else '❌ NOT SET'}")
print(f"  DB_NAME: {db_name or '❌ NOT SET'}")

if not all([db_host, db_port, db_user, db_password, db_name]):
    print()
    print("❌ Some database settings are missing!")
    print("   Please check your .env file")
    sys.exit(1)

print()

# Test 5: Try to import config.settings
print("⚙️  Testing config.settings...")
try:
    from config import settings
    print("✅ config.settings imported successfully")
    print(f"  DATABASE_HOST: {settings.DATABASE_HOST}")
    print(f"  DATABASE_PORT: {settings.DATABASE_PORT}")
    print(f"  DATABASE_USER: {settings.DATABASE_USER}")
    print(f"  DATABASE_PASSWORD: {'***' if settings.DATABASE_PASSWORD else '❌ EMPTY'}")
    print(f"  DATABASE_NAME: {settings.DATABASE_NAME}")
except Exception as e:
    print(f"❌ Failed to import config.settings: {e}")
    sys.exit(1)

print()

# Test 6: Test PostgreSQL connection
print("🔌 Testing PostgreSQL connection...")
import asyncio
import asyncpg

async def test_connection():
    try:
        conn = await asyncpg.connect(
            host=settings.DATABASE_HOST,
            port=settings.DATABASE_PORT,
            user=settings.DATABASE_USER,
            password=settings.DATABASE_PASSWORD,
            database=settings.DATABASE_NAME,
            timeout=10
        )
        version = await conn.fetchval('SELECT version()')
        await conn.close()
        print(f"✅ PostgreSQL connection successful!")
        print(f"  Version: {version.split(',')[0]}")
        return True
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        print()
        print("Troubleshooting:")
        print("1. Check PostgreSQL is running: sudo systemctl status postgresql")
        print("2. Check credentials are correct:")
        print(f"   psql -U {settings.DATABASE_USER} -d {settings.DATABASE_NAME} -h {settings.DATABASE_HOST}")
        print("3. Check password in .env matches PostgreSQL user password")
        return False

try:
    success = asyncio.run(test_connection())
    if not success:
        sys.exit(1)
except Exception as e:
    print(f"❌ Error testing connection: {e}")
    sys.exit(1)

print()
print("=" * 80)
print("✅ All configuration tests passed!")
print("=" * 80)
print()
print("You can now run: python3 init_database.py")

