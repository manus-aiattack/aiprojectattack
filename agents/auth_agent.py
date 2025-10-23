from core.data_models import Strategy, AuthReport, AuthFinding, AttackPhase, ReconData, ErrorType
from core.logger import log
import json
import re
from urllib.parse import urlparse, urljoin
import os
import asyncio
from typing import Optional

from core.base_agent import BaseAgent


class Auth_Agent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["jwt_tool", "hydra"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.recon_data: Optional[ReconData] = None
        self.report_class = AuthReport # Set report class

    async def setup(self):
        """Asynchronous setup method for Auth_Agent."""
        self.recon_data = await self.context_manager.get_context('recon_data')

    async def run(self, strategy: Strategy = None, **kwargs) -> AuthReport:
        log.info("Auth Agent: Running placeholder run method.")
        # Placeholder implementation for now
        return self.create_report(
            summary="Auth Agent is not fully implemented yet. Placeholder report.",
            errors=["Agent not fully implemented."],
            error_type=ErrorType.LOGIC
        )

    def _find_login_pages(self) -> list:
        log.info("Auth Agent: Searching for login pages...")
        login_pages = []
        keywords = ['login', 'signin', 'auth', 'account', 'panel', 'admin']
        if not self.recon_data or not self.recon_data.http_servers:
            return []
        for url in self.recon_data.http_servers:
            if any(keyword in url.lower() for keyword in keywords):
                login_pages.append(url)
        return login_pages
