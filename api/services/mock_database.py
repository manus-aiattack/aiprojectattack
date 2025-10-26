"""
Mock Database Service for Testing
Provides in-memory storage for development and testing
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from collections import defaultdict


class MockDatabase:
    """
    Mock database implementation using in-memory storage
    Simulates async database operations
    """
    
    def __init__(self):
        self.targets: Dict[str, Dict] = {}
        self.campaigns: Dict[str, Dict] = {}
        self.users: Dict[str, Dict] = {}
        self.api_keys: Dict[str, Dict] = {}
        self.attacks: Dict[str, Dict] = {}
        self.logs: Dict[str, List[Dict]] = defaultdict(list)
        self.files: Dict[str, List[Dict]] = defaultdict(list)
        self.connected = False
        
        # Initialize default admin user
        self._init_default_users()
    
    def _init_default_users(self):
        """Initialize default users for testing"""
        admin_key = "admin_test_key_12345"
        user_key = "user_test_key_67890"
        
        self.users["admin_id"] = {
            "id": "admin_id",
            "username": "admin",
            "email": "admin@dlnk.local",
            "role": "admin",
            "is_active": True,
            "quota": 1000,
            "quota_used": 0,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.users["user_id"] = {
            "id": "user_id",
            "username": "testuser",
            "email": "user@dlnk.local",
            "role": "user",
            "is_active": True,
            "quota": 100,
            "quota_used": 0,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.api_keys[admin_key] = {
            "api_key": admin_key,
            "user_id": "admin_id",
            "is_active": True,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.api_keys[user_key] = {
            "api_key": user_key,
            "user_id": "user_id",
            "is_active": True,
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def connect(self):
        """Simulate database connection"""
        await asyncio.sleep(0.1)
        self.connected = True
    
    async def disconnect(self):
        """Simulate database disconnection"""
        await asyncio.sleep(0.1)
        self.connected = False
    
    async def health_check(self) -> bool:
        """Check database health"""
        return self.connected
    
    # ========================================================================
    # Target Operations
    # ========================================================================
    
    async def save_target(self, target_data: Dict) -> Dict:
        """Save a target"""
        target_id = target_data.get("target_id")
        self.targets[target_id] = target_data
        return target_data
    
    async def get_target(self, target_id: str) -> Optional[Dict]:
        """Get a target by ID"""
        return self.targets.get(target_id)
    
    async def get_user_targets(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get all targets for a user"""
        user_targets = [
            t for t in self.targets.values()
            if t.get("metadata", {}).get("created_by") == user_id
        ]
        return user_targets[:limit]
    
    async def delete_target(self, target_id: str) -> bool:
        """Delete a target"""
        if target_id in self.targets:
            del self.targets[target_id]
            return True
        return False
    
    # ========================================================================
    # Campaign Operations
    # ========================================================================
    
    async def save_campaign(self, campaign_data: Dict) -> Dict:
        """Save a campaign"""
        campaign_id = campaign_data.get("campaign_id")
        self.campaigns[campaign_id] = campaign_data
        return campaign_data
    
    async def get_campaign(self, campaign_id: str) -> Optional[Dict]:
        """Get a campaign by ID"""
        return self.campaigns.get(campaign_id)
    
    async def update_campaign(self, campaign_id: str, campaign_data: Dict) -> Dict:
        """Update a campaign"""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].update(campaign_data)
            return self.campaigns[campaign_id]
        return campaign_data
    
    async def get_all_campaigns(self, limit: int = 50, status: Optional[str] = None) -> List[Dict]:
        """Get all campaigns"""
        campaigns = list(self.campaigns.values())
        if status:
            campaigns = [c for c in campaigns if c.get("status") == status]
        return campaigns[:limit]
    
    async def get_user_campaigns(self, user_id: str, limit: int = 50, status: Optional[str] = None) -> List[Dict]:
        """Get campaigns for a user"""
        user_campaigns = []
        for campaign in self.campaigns.values():
            targets = campaign.get("targets", [])
            if any(t.get("metadata", {}).get("created_by") == user_id for t in targets):
                if not status or campaign.get("status") == status:
                    user_campaigns.append(campaign)
        return user_campaigns[:limit]
    
    async def delete_campaign(self, campaign_id: str) -> bool:
        """Delete a campaign"""
        if campaign_id in self.campaigns:
            del self.campaigns[campaign_id]
            return True
        return False
    
    # ========================================================================
    # Attack Operations (Legacy compatibility)
    # ========================================================================
    
    async def get_attack(self, attack_id: str) -> Optional[Dict]:
        """Get an attack by ID"""
        return self.attacks.get(attack_id)
    
    async def save_attack(self, attack_data: Dict) -> Dict:
        """Save an attack"""
        attack_id = attack_data.get("attack_id", attack_data.get("id"))
        self.attacks[attack_id] = attack_data
        return attack_data
    
    async def get_all_attacks(self, limit: int = 50) -> List[Dict]:
        """Get all attacks"""
        return list(self.attacks.values())[:limit]
    
    async def get_user_attacks(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get attacks for a user"""
        user_attacks = [
            a for a in self.attacks.values()
            if a.get("user_id") == user_id
        ]
        return user_attacks[:limit]
    
    async def get_active_attacks_count(self) -> int:
        """Get count of active attacks"""
        return sum(1 for a in self.attacks.values() if a.get("status") == "running")
    
    # ========================================================================
    # Log Operations
    # ========================================================================
    
    async def add_attack_log(self, attack_id: str, log_entry: Dict):
        """Add a log entry for an attack"""
        self.logs[attack_id].append({
            **log_entry,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def get_attack_logs(self, attack_id: str, limit: int = 100) -> List[Dict]:
        """Get logs for an attack"""
        logs = self.logs.get(attack_id, [])
        return logs[-limit:]
    
    # ========================================================================
    # File Operations
    # ========================================================================
    
    async def add_attack_file(self, attack_id: str, file_data: Dict):
        """Add a file for an attack"""
        self.files[attack_id].append({
            **file_data,
            "uploaded_at": datetime.utcnow().isoformat()
        })
    
    async def get_attack_files(self, attack_id: str) -> List[Dict]:
        """Get files for an attack"""
        return self.files.get(attack_id, [])
    
    # ========================================================================
    # User & Auth Operations
    # ========================================================================
    
    async def get_user_by_api_key(self, api_key: str) -> Optional[Dict]:
        """Get user by API key"""
        key_data = self.api_keys.get(api_key)
        if not key_data or not key_data.get("is_active"):
            return None
        
        user_id = key_data.get("user_id")
        user = self.users.get(user_id)
        
        if user:
            return {**user, "api_key": api_key}
        return None
    
    async def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    async def update_user_quota(self, user_id: str, quota_used: int):
        """Update user quota"""
        if user_id in self.users:
            self.users[user_id]["quota_used"] = quota_used
    
    async def create_user(self, user_data: Dict) -> Dict:
        """Create a new user"""
        user_id = user_data.get("id")
        self.users[user_id] = user_data
        return user_data
    
    async def create_api_key(self, user_id: str, api_key: str) -> Dict:
        """Create an API key"""
        key_data = {
            "api_key": api_key,
            "user_id": user_id,
            "is_active": True,
            "created_at": datetime.utcnow().isoformat()
        }
        self.api_keys[api_key] = key_data
        return key_data
    
    # ========================================================================
    # Statistics
    # ========================================================================
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        return {
            "total_users": len(self.users),
            "total_targets": len(self.targets),
            "total_campaigns": len(self.campaigns),
            "total_attacks": len(self.attacks),
            "active_campaigns": sum(1 for c in self.campaigns.values() if c.get("status") == "running"),
            "active_attacks": sum(1 for a in self.attacks.values() if a.get("status") == "running")
        }

