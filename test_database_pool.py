#!/usr/bin/env python3
"""
Test Database Pool Operations with @require_pool decorator
"""

import asyncio
import sys
import os
from loguru import logger

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from api.database.db_service import DatabaseService


async def test_pool_decorator():
    """Test database pool decorator"""
    
    logger.info("=" * 60)
    logger.info("Testing Database Pool Decorator")
    logger.info("=" * 60)
    
    db = DatabaseService()
    
    # Test 1: Try to use database before connecting (should fail)
    logger.info("\n[Test 1] Attempting to use database before connecting...")
    try:
        await db.get_attack_statistics()
        logger.error("❌ Test 1 FAILED: Should have raised RuntimeError")
    except RuntimeError as e:
        logger.success(f"✅ Test 1 PASSED: Correctly raised error: {e}")
    except Exception as e:
        logger.error(f"❌ Test 1 FAILED: Wrong exception type: {e}")
    
    # Test 2: Connect to database
    logger.info("\n[Test 2] Connecting to database...")
    try:
        await db.connect()
        logger.success("✅ Test 2 PASSED: Database connected successfully")
    except Exception as e:
        logger.error(f"❌ Test 2 FAILED: Connection failed: {e}")
        return
    
    # Test 3: Test save operations
    logger.info("\n[Test 3] Testing save operations...")
    try:
        # Create API key
        api_key = await db.create_api_key(
            key_type="admin",
            user_name="test_user",
            expires_in_days=30,
            notes="Test key for pool decorator"
        )
        logger.success(f"✅ Test 3a PASSED: API key created: {api_key['key_value']}")
        
        # Create attack
        attack = await db.create_attack(
            key_id=api_key['id'],
            target_url="https://example.com",
            attack_mode="auto"
        )
        logger.success(f"✅ Test 3b PASSED: Attack created: {attack['id']}")
        
        # Create vulnerability
        vuln = await db.create_vulnerability(
            attack_id=attack['id'],
            vuln_type="xss",
            severity="high",
            title="Test XSS Vulnerability",
            description="Test vulnerability for pool decorator",
            url="https://example.com/test"
        )
        logger.success(f"✅ Test 3c PASSED: Vulnerability created: {vuln['id']}")
        
    except Exception as e:
        logger.error(f"❌ Test 3 FAILED: Save operation failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 4: Test load operations
    logger.info("\n[Test 4] Testing load operations...")
    try:
        # Get API key
        key = await db.get_api_key(api_key['key_value'])
        logger.success(f"✅ Test 4a PASSED: API key loaded: {key['user_name']}")
        
        # Get attack
        attack_data = await db.get_attack(attack['id'])
        logger.success(f"✅ Test 4b PASSED: Attack loaded: {attack_data['target_url']}")
        
        # List vulnerabilities
        vulns = await db.list_vulnerabilities(attack['id'])
        logger.success(f"✅ Test 4c PASSED: Vulnerabilities loaded: {len(vulns)} found")
        
        # Get statistics
        stats = await db.get_attack_statistics()
        logger.success(f"✅ Test 4d PASSED: Statistics loaded: {stats['total_attacks']} total attacks")
        
    except Exception as e:
        logger.error(f"❌ Test 4 FAILED: Load operation failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 5: Test update operations
    logger.info("\n[Test 5] Testing update operations...")
    try:
        # Update attack
        updated_attack = await db.update_attack(
            attack['id'],
            status='completed',
            vulnerabilities_found=1
        )
        logger.success(f"✅ Test 5a PASSED: Attack updated: status={updated_attack['status']}")
        
        # Update API key
        updated_key = await db.update_api_key(
            api_key['id'],
            notes="Updated test key"
        )
        logger.success(f"✅ Test 5b PASSED: API key updated: {updated_key['notes']}")
        
    except Exception as e:
        logger.error(f"❌ Test 5 FAILED: Update operation failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 6: Disconnect and try to use (should fail)
    logger.info("\n[Test 6] Testing after disconnect...")
    try:
        await db.disconnect()
        logger.info("Database disconnected")
        
        # This should fail
        await db.get_attack_statistics()
        logger.error("❌ Test 6 FAILED: Should have raised error after disconnect")
        
    except RuntimeError as e:
        logger.success(f"✅ Test 6 PASSED: Correctly raised error after disconnect: {e}")
    except Exception as e:
        logger.warning(f"⚠️  Test 6: Different error type: {e}")
    
    logger.info("\n" + "=" * 60)
    logger.info("Database Pool Decorator Tests Completed")
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_pool_decorator())

