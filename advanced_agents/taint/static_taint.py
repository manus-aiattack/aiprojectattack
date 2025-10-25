"""
import os
import os
Static Taint Analysis using Semgrep
"""

import asyncio
import subprocess
import json
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class StaticTaintAnalyzer:
    """Static taint analysis using Semgrep"""
    
    def __init__(self):
        self.rules = []
    
    async def analyze_code(self, code: str, language: str = "python") -> Dict:
        """Analyze code for taint flows"""
        log.info(f"[StaticTaint] Analyzing {language} code")
        
        # Write code to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language}', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            # Run semgrep (if available)
            result = subprocess.run(
                ['semgrep', '--json', '--config=auto', temp_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                findings = json.loads(result.stdout)
                return {'taint_flows': findings.get('results', [])}
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            log.warning("[StaticTaint] Semgrep not available, using fallback")
        
        finally:
            os.unlink(temp_file)
        
        # Fallback: simple pattern matching
        return await self._fallback_analysis(code)
    
    async def _fallback_analysis(self, code: str) -> Dict:
        """Fallback analysis without Semgrep"""
        taint_sources = ['input(', 'request.', 'sys.argv']
        taint_sinks = ['eval(', 'exec(', 'os.system(', 'subprocess.']
        
        flows = []
        for source in taint_sources:
            if source in code:
                for sink in taint_sinks:
                    if sink in code:
                        flows.append({
                            'source': source,
                            'sink': sink,
                            'severity': 'HIGH'
                        })
        
        return {'taint_flows': flows}
