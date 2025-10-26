#!/usr/bin/env python3
"""
Test script for API endpoints after fixes
"""

import asyncio
import aiohttp
import sys

API_BASE = "http://localhost:8000"

async def test_api():
    """Test API endpoints"""
    print("=" * 60)
    print("Testing dLNk Attack Platform API")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Health check
        print("\n[1/4] Testing health endpoint...")
        try:
            async with session.get(f"{API_BASE}/health") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Health check passed: {data}")
                else:
                    print(f"❌ Health check failed: {resp.status}")
        except Exception as e:
            print(f"❌ Health check error: {e}")
            print("⚠️  API server may not be running. Start it with: cd manus && python3 main.py server")
            return False
        
        # Test 2: Get admin key
        print("\n[2/4] Reading admin key...")
        try:
            with open("workspace/ADMIN_KEY.txt", "r") as f:
                admin_key = f.read().strip()
                print(f"✅ Admin key loaded: {admin_key[:20]}...")
        except FileNotFoundError:
            print("❌ Admin key not found. Run: cd manus && python3 startup.py")
            return False
        
        headers = {"X-API-Key": admin_key}
        
        # Test 3: Test attack status endpoint (should return 404 for non-existent attack)
        print("\n[3/4] Testing attack status endpoint...")
        test_attack_id = "test-attack-123"
        try:
            async with session.get(
                f"{API_BASE}/api/attack/{test_attack_id}/status",
                headers=headers
            ) as resp:
                if resp.status == 404:
                    print(f"✅ Status endpoint working (404 for non-existent attack)")
                elif resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Status endpoint working: {data}")
                else:
                    print(f"⚠️  Status endpoint returned: {resp.status}")
                    text = await resp.text()
                    print(f"Response: {text[:200]}")
        except Exception as e:
            print(f"❌ Status endpoint error: {e}")
        
        # Test 4: Test attack logs endpoint
        print("\n[4/4] Testing attack logs endpoint...")
        try:
            async with session.get(
                f"{API_BASE}/api/attack/{test_attack_id}/logs",
                headers=headers
            ) as resp:
                if resp.status == 404:
                    print(f"✅ Logs endpoint working (404 for non-existent attack)")
                elif resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Logs endpoint working: {data}")
                else:
                    print(f"⚠️  Logs endpoint returned: {resp.status}")
                    text = await resp.text()
                    print(f"Response: {text[:200]}")
        except Exception as e:
            print(f"❌ Logs endpoint error: {e}")
    
    print("\n" + "=" * 60)
    print("API Test Complete")
    print("=" * 60)
    return True

if __name__ == "__main__":
    result = asyncio.run(test_api())
    sys.exit(0 if result else 1)

