"""
Taint Source Identifier
"""

import asyncio
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class SourceIdentifier:
    """Identifies taint sources"""
    
    def __init__(self):
        self.sources = {
            'user_input': ['input(', 'raw_input(', 'sys.argv', 'request.'],
            'file_input': ['open(', 'read(', 'readlines('],
            'network_input': ['socket.recv', 'urllib.request', 'requests.get'],
            'database_input': ['cursor.execute', 'query(']
        }
    
    async def identify_sources(self, code: str) -> List[Dict]:
        """Identify taint sources in code"""
        log.info("[SourceIdentifier] Identifying sources")
        
        identified = []
        
        for source_type, patterns in self.sources.items():
            for pattern in patterns:
                if pattern in code:
                    identified.append({
                        'type': source_type,
                        'source': pattern
                    })
        
        return identified
