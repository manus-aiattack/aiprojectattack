"""
Weaponized 0-day Hunter Agent
ค้นหาช่องโหว่ 0-day ด้วย Fuzzing และ Code Analysis
"""

import asyncio
import hashlib
import os
import subprocess
import json
from typing import Dict, List, Any, Optional

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class ZeroDayHunterAgent(BaseAgent):
    """
    Weaponized 0-day Hunter Agent
    
    Features:
    - AFL++ fuzzing integration
    - Semgrep code analysis
    - Crash analysis and triage
    - Exploit generation
    - CVE-like vulnerability reporting
    """
    
    supported_phases = [AttackPhase.RECONNAISSANCE, AttackPhase.EXPLOITATION]
    required_tools = ["afl-fuzz", "semgrep"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.results_dir = "/home/ubuntu/dlnk/workspace/loot/zero_day"
        self.fuzzing_dir = "/home/ubuntu/dlnk/workspace/fuzzing"
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.fuzzing_dir, exist_ok=True)

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "fuzz", "analyze", "triage", "exploit"
            context: {
                "target_binary": path to binary for fuzzing,
                "target_source": path to source code for analysis,
                "timeout": fuzzing timeout in seconds,
                "input_dir": directory with seed inputs
            }
        """
        log.info(f"[ZeroDayHunterAgent] Starting with directive: {directive}")

        try:
            if directive == "fuzz":
                result = await self._fuzz_target(context)
            elif directive == "analyze":
                result = await self._analyze_code(context)
            elif directive == "triage":
                result = await self._triage_crashes(context)
            elif directive == "exploit":
                result = await self._generate_exploit(context)
            else:
                result = await self._full_hunt(context)
            
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[ZeroDayHunterAgent] Error: {e}")
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _fuzz_target(self, context: Dict) -> Dict:
        """Fuzz target binary with AFL++"""
        log.info("[ZeroDayHunterAgent] Starting AFL++ fuzzing...")
        
        target_binary = context.get("target_binary")
        if not target_binary or not os.path.exists(target_binary):
            return {
                "success": False,
                "error": "Target binary not found"
            }
        
        timeout = context.get("timeout", 3600)  # 1 hour default
        input_dir = context.get("input_dir", f"{self.fuzzing_dir}/inputs")
        output_dir = f"{self.fuzzing_dir}/outputs"
        
        # Create input directory with seed files
        os.makedirs(input_dir, exist_ok=True)
        if not os.listdir(input_dir):
            # Create basic seed files
            with open(f"{input_dir}/seed1.txt", "w") as f:
                f.write("test\n")
            with open(f"{input_dir}/seed2.txt", "w") as f:
                f.write("A" * 100 + "\n")
        
        # Check if AFL++ is installed
        if not self._check_tool("afl-fuzz"):
            return {
                "success": False,
                "error": "AFL++ not installed. Install with: sudo apt install afl++",
                "install_command": "sudo apt-get update && sudo apt-get install -y afl++"
            }
        
        # Run AFL++
        afl_command = [
            "timeout", str(timeout),
            "afl-fuzz",
            "-i", input_dir,
            "-o", output_dir,
            "-m", "none",  # No memory limit
            "--", target_binary, "@@"
        ]
        
        log.info(f"[ZeroDayHunterAgent] Running: {' '.join(afl_command)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *afl_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Check for crashes
            crashes_dir = f"{output_dir}/default/crashes"
            crashes = []
            
            if os.path.exists(crashes_dir):
                crash_files = [f for f in os.listdir(crashes_dir) if f.startswith("id:")]
                crashes = crash_files
                
                log.success(f"[ZeroDayHunterAgent] Found {len(crashes)} crashes!")
            
            result = {
                "success": len(crashes) > 0,
                "target": target_binary,
                "fuzzing_time": timeout,
                "crashes_found": len(crashes),
                "crashes": crashes,
                "output_dir": output_dir,
                "output_file": self._save_results("fuzzing", {
                    "target": target_binary,
                    "crashes": crashes
                })
            }
            
            return result
            
        except Exception as e:
            log.error(f"[ZeroDayHunterAgent] Fuzzing failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _analyze_code(self, context: Dict) -> Dict:
        """Analyze source code with Semgrep"""
        log.info("[ZeroDayHunterAgent] Starting Semgrep code analysis...")
        
        target_source = context.get("target_source")
        if not target_source or not os.path.exists(target_source):
            return {
                "success": False,
                "error": "Target source not found"
            }
        
        # Check if Semgrep is installed
        if not self._check_tool("semgrep"):
            return {
                "success": False,
                "error": "Semgrep not installed. Install with: pip install semgrep",
                "install_command": "pip3 install semgrep"
            }
        
        # Run Semgrep with security rules
        semgrep_command = [
            "semgrep",
            "--config=auto",
            "--json",
            target_source
        ]
        
        log.info(f"[ZeroDayHunterAgent] Running: {' '.join(semgrep_command)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *semgrep_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            results = json.loads(stdout.decode())
            findings = results.get("results", [])
            
            # Filter high severity findings
            high_severity = [f for f in findings if f.get("extra", {}).get("severity") in ["ERROR", "WARNING"]]
            
            log.success(f"[ZeroDayHunterAgent] Found {len(high_severity)} potential vulnerabilities!")
            
            result = {
                "success": len(high_severity) > 0,
                "target": target_source,
                "total_findings": len(findings),
                "high_severity_findings": len(high_severity),
                "findings": high_severity[:10],  # Top 10
                "output_file": self._save_results("code_analysis", {
                    "target": target_source,
                    "findings": high_severity
                })
            }
            
            return result
            
        except Exception as e:
            log.error(f"[ZeroDayHunterAgent] Code analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _triage_crashes(self, context: Dict) -> Dict:
        """Triage crashes to find exploitable bugs"""
        log.info("[ZeroDayHunterAgent] Triaging crashes...")
        
        crashes_dir = context.get("crashes_dir", f"{self.fuzzing_dir}/outputs/default/crashes")
        target_binary = context.get("target_binary")
        
        if not os.path.exists(crashes_dir):
            return {
                "success": False,
                "error": "Crashes directory not found"
            }
        
        crash_files = [f for f in os.listdir(crashes_dir) if f.startswith("id:")]
        
        if not crash_files:
            return {
                "success": False,
                "message": "No crashes to triage"
            }
        
        exploitable_crashes = []
        
        for crash_file in crash_files[:20]:  # Triage first 20 crashes
            crash_path = os.path.join(crashes_dir, crash_file)
            
            # Run target with crash input
            try:
                process = await asyncio.create_subprocess_exec(
                    target_binary,
                    crash_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
                
                # Check for exploitable conditions
                stderr_text = stderr.decode()
                
                if any(keyword in stderr_text.lower() for keyword in [
                    "segmentation fault",
                    "stack smashing",
                    "heap corruption",
                    "use after free",
                    "double free"
                ]):
                    exploitable_crashes.append({
                        "file": crash_file,
                        "type": self._identify_crash_type(stderr_text),
                        "exploitability": "high"
                    })
                    log.success(f"[ZeroDayHunterAgent] Found exploitable crash: {crash_file}")
                
            except asyncio.TimeoutError:
                log.debug(f"[ZeroDayHunterAgent] Crash {crash_file} caused hang")
            except Exception as e:
                log.debug(f"[ZeroDayHunterAgent] Error triaging {crash_file}: {e}")
        
        result = {
            "success": len(exploitable_crashes) > 0,
            "total_crashes": len(crash_files),
            "exploitable_crashes": len(exploitable_crashes),
            "crashes": exploitable_crashes,
            "output_file": self._save_results("triage", exploitable_crashes)
        }
        
        if exploitable_crashes:
            log.success(f"[ZeroDayHunterAgent] Found {len(exploitable_crashes)} exploitable crashes!")
        
        return result

    def _identify_crash_type(self, stderr: str) -> str:
        """Identify crash type from stderr"""
        stderr_lower = stderr.lower()
        
        if "segmentation fault" in stderr_lower or "sigsegv" in stderr_lower:
            return "segmentation_fault"
        elif "stack smashing" in stderr_lower or "stack overflow" in stderr_lower:
            return "stack_overflow"
        elif "heap corruption" in stderr_lower:
            return "heap_corruption"
        elif "use after free" in stderr_lower:
            return "use_after_free"
        elif "double free" in stderr_lower:
            return "double_free"
        elif "null pointer" in stderr_lower:
            return "null_pointer_dereference"
        else:
            return "unknown"

    async def _generate_exploit(self, context: Dict) -> Dict:
        """Generate exploit for crash"""
        log.info("[ZeroDayHunterAgent] Generating exploit...")
        
        crash_file = context.get("crash_file")
        crash_type = context.get("crash_type", "unknown")
        
        if not crash_file or not os.path.exists(crash_file):
            return {
                "success": False,
                "error": "Crash file not found"
            }
        
        # Read crash input
        with open(crash_file, "rb") as f:
            crash_input = f.read()
        
        # Generate exploit template based on crash type
        exploit_template = self._generate_exploit_template(crash_type, crash_input)
        
        # Save exploit
        exploit_file = os.path.join(self.results_dir, f"exploit_{os.path.basename(crash_file)}.py")
        with open(exploit_file, "w") as f:
            f.write(exploit_template)
        
        result = {
            "success": True,
            "crash_file": crash_file,
            "crash_type": crash_type,
            "exploit_file": exploit_file,
            "exploit_template": exploit_template[:500]  # First 500 chars
        }
        
        log.success(f"[ZeroDayHunterAgent] Exploit generated: {exploit_file}")
        return result

    def _generate_exploit_template(self, crash_type: str, crash_input: bytes) -> str:
        """Generate exploit template"""
        template = f"""#!/usr/bin/env python3
\"\"\"
Exploit for {crash_type}
Generated by dLNk dLNk 0-day Hunter
\"\"\"

import struct
import socket

# Original crash input
crash_input = {repr(crash_input)}

# TODO: Modify payload for exploitation
payload = crash_input

# TODO: Add shellcode
shellcode = b"\\x90" * 100  # NOP sled

# TODO: Add return address
ret_addr = struct.pack("<Q", 0x41414141)  # Replace with actual address

# Final exploit
exploit = payload + shellcode + ret_addr

# TODO: Send exploit to target
# Example for network service:
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(("target", port))
# s.send(exploit)
# s.close()

print(f"Exploit length: {{len(exploit)}}")
print(f"Exploit: {{exploit.hex()}}")
"""
        return template

    async def _full_hunt(self, context: Dict) -> Dict:
        """Full 0-day hunting workflow"""
        log.info("[ZeroDayHunterAgent] Starting full 0-day hunt...")
        
        results = {}
        
        # Step 1: Code analysis
        if context.get("target_source"):
            log.info("[ZeroDayHunterAgent] Step 1: Code analysis...")
            results["code_analysis"] = await self._analyze_code(context)
        
        # Step 2: Fuzzing
        if context.get("target_binary"):
            log.info("[ZeroDayHunterAgent] Step 2: Fuzzing...")
            results["fuzzing"] = await self._fuzz_target(context)
            
            # Step 3: Triage crashes
            if results["fuzzing"].get("success"):
                log.info("[ZeroDayHunterAgent] Step 3: Triaging crashes...")
                results["triage"] = await self._triage_crashes(context)
                
                # Step 4: Generate exploits
                if results["triage"].get("success"):
                    log.info("[ZeroDayHunterAgent] Step 4: Generating exploits...")
                    exploitable_crashes = results["triage"]["crashes"]
                    
                    results["exploits"] = []
                    for crash in exploitable_crashes[:5]:  # Top 5
                        exploit_result = await self._generate_exploit({
                            "crash_file": os.path.join(
                                context.get("crashes_dir", f"{self.fuzzing_dir}/outputs/default/crashes"),
                                crash["file"]
                            ),
                            "crash_type": crash["type"]
                        })
                        results["exploits"].append(exploit_result)
        
        result = {
            "success": any(r.get("success") for r in results.values() if isinstance(r, dict)),
            "results": results,
            "output_file": self._save_results("full_hunt", results)
        }
        
        log.success("[ZeroDayHunterAgent] 0-day hunt complete!")
        return result

    def _check_tool(self, tool_name: str) -> bool:
        """Check if tool is installed"""
        try:
            subprocess.run([tool_name, "--version"], capture_output=True, timeout=5)
            return True
        except:
            return False

    def _save_results(self, operation: str, data: Any) -> str:
        """Save results"""
        filename = f"zero_day_{operation}_{int(asyncio.get_event_loop().time())}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            return filepath
        except Exception as e:
            log.error(f"[ZeroDayHunterAgent] Failed to save results: {e}")
            return ""

