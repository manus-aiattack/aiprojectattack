"""BloodHound Agent - Map AD attack paths"""
import asyncio, os, json
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class BloodHoundAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="BloodHoundAgent", description="Collect and analyze AD attack paths", version="1.0.0")
        self.output_dir = "workspace/bloodhound"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, username, password = strategy.get('domain'), strategy.get('username'), strategy.get('password')
            dc_ip = strategy.get('dc_ip')
            
            if not all([domain, username, password]):
                return AgentData(success=False, errors=["Missing credentials"])
            
            cmd = ['bloodhound-python', '-d', domain, '-u', username, '-p', password, '-c', 'All', '--zip']
            if dc_ip:
                cmd.extend(['-dc', dc_ip])
            
            process = await asyncio.create_subprocess_exec(*cmd, cwd=self.output_dir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            zip_files = [f for f in os.listdir(self.output_dir) if f.endswith('.zip')]
            return AgentData(success=len(zip_files) > 0, data={'output_files': zip_files, 'output_dir': self.output_dir})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
