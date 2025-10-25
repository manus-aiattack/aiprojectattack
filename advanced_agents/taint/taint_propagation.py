"""
Taint Propagation Rules
"""

import asyncio
from typing import Dict, List, Set
import logging

log = logging.getLogger(__name__)


class TaintPropagationEngine:
    """Taint propagation engine"""
    
    def __init__(self):
        self.tainted_vars = set()
        self.propagation_rules = {}
    
    async def mark_tainted(self, variable: str):
        """Mark variable as tainted"""
        self.tainted_vars.add(variable)
        log.debug(f"[TaintPropagation] Marked {variable} as tainted")
    
    async def propagate(self, from_var: str, to_var: str):
        """Propagate taint from one variable to another"""
        if from_var in self.tainted_vars:
            await self.mark_tainted(to_var)
    
    async def is_tainted(self, variable: str) -> bool:
        """Check if variable is tainted"""
        return variable in self.tainted_vars
    
    async def get_tainted_variables(self) -> Set[str]:
        """Get all tainted variables"""
        return self.tainted_vars.copy()
