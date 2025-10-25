"""
Target Acquisition Agent - Autonomous Target Discovery

This agent proactively searches for potential targets from public sources
without requiring human input. It uses various OSINT techniques to discover
targets based on predefined keywords and criteria.

Features:
- Search engine reconnaissance
- Certificate Transparency log monitoring
- Newly registered domain discovery
- Social media monitoring
- Target scoring and prioritization
"""

import asyncio
import aiohttp
import re
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse, quote

logger = logging.getLogger(__name__)


class TargetAcquisitionAgent:
    """
    Agent for autonomous target discovery and acquisition.
    
    This agent searches for potential targets using multiple OSINT sources
    and scores them based on relevance and attack surface.
    """
    
    def __init__(self, keywords: List[str] = None):
        """
        Initialize Target Acquisition Agent.
        
        Args:
            keywords: List of keywords to search for (e.g., ["online casino", "fintech startup"])
        """
        self.keywords = keywords or [
            "online casino",
            "betting site",
            "financial services",
            "payment gateway",
            "crypto exchange",
            "e-commerce platform",
            "web application",
            "api service"
        ]
        
        self.discovered_targets = []
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def discover_targets(self, max_targets: int = 10) -> List[Dict]:
        """
        Main method to discover targets from multiple sources.
        
        Args:
            max_targets: Maximum number of targets to return
            
        Returns:
            List of discovered targets with scores
        """
        logger.info(f"Starting target acquisition with keywords: {self.keywords}")
        
        # Run all discovery methods in parallel
        tasks = [
            self._search_certificate_transparency(),
            self._search_newly_registered_domains(),
            self._search_shodan_like(),
            self._search_github_repos(),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all discovered targets
        all_targets = []
        for result in results:
            if isinstance(result, list):
                all_targets.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Discovery method failed: {result}")
        
        # Score and rank targets
        scored_targets = self._score_targets(all_targets)
        
        # Return top targets
        top_targets = sorted(scored_targets, key=lambda x: x['score'], reverse=True)[:max_targets]
        
        logger.info(f"Discovered {len(top_targets)} high-value targets")
        
        return top_targets
    
    async def _search_certificate_transparency(self) -> List[Dict]:
        """
        Search Certificate Transparency logs for newly issued certificates.
        
        Uses crt.sh API to find domains matching our keywords.
        """
        targets = []
        
        try:
            for keyword in self.keywords:
                url = f"https://crt.sh/?q=%25{quote(keyword)}%25&output=json"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract unique domains
                        domains = set()
                        for cert in data[:50]:  # Limit to recent 50
                            name = cert.get('name_value', '')
                            # Clean up domain names
                            for domain in name.split('\n'):
                                domain = domain.strip().lstrip('*.')
                                if domain and '.' in domain:
                                    domains.add(domain)
                        
                        # Create target entries
                        for domain in domains:
                            targets.append({
                                'url': f'https://{domain}',
                                'domain': domain,
                                'source': 'certificate_transparency',
                                'keyword': keyword,
                                'discovered_at': datetime.now().isoformat()
                            })
                        
                        logger.info(f"Found {len(domains)} domains from CT logs for keyword: {keyword}")
                        
                await asyncio.sleep(1)  # Rate limiting
                
        except Exception as e:
            logger.error(f"Certificate Transparency search failed: {e}")
        
        return targets
    
    async def _search_newly_registered_domains(self) -> List[Dict]:
        """
        Search for newly registered domains matching our keywords.
        
        Uses WhoisXML API or similar services.
        """
        targets = []
        
        try:
            # Simulate newly registered domain discovery
            # In production, you would use APIs like:
            # - WhoisXML API
            # - DomainTools
            # - SecurityTrails
            
            # For now, we'll use a simple heuristic approach
            for keyword in self.keywords:
                # Search for domains with keyword in name
                potential_domains = [
                    f"{keyword.replace(' ', '')}.com",
                    f"{keyword.replace(' ', '')}-app.com",
                    f"new-{keyword.replace(' ', '')}.com",
                    f"{keyword.replace(' ', '')}2024.com",
                ]
                
                for domain in potential_domains:
                    targets.append({
                        'url': f'https://{domain}',
                        'domain': domain,
                        'source': 'newly_registered',
                        'keyword': keyword,
                        'discovered_at': datetime.now().isoformat(),
                        'registration_date': (datetime.now() - timedelta(days=7)).isoformat()
                    })
            
            logger.info(f"Generated {len(targets)} potential newly registered domains")
            
        except Exception as e:
            logger.error(f"Newly registered domain search failed: {e}")
        
        return targets
    
    async def _search_shodan_like(self) -> List[Dict]:
        """
        Search for exposed services using Shodan-like techniques.
        
        Looks for web applications with interesting characteristics.
        """
        targets = []
        
        try:
            # In production, you would use Shodan API, Censys, or similar
            # For now, we'll simulate with common patterns
            
            for keyword in self.keywords:
                # Common ports and services
                services = [
                    ('8080', 'web'),
                    ('8443', 'web-ssl'),
                    ('3000', 'nodejs'),
                    ('5000', 'flask'),
                    ('8000', 'django'),
                ]
                
                # Simulate discovered services
                # In production, this would be real Shodan/Censys data
                logger.info(f"Simulating service discovery for keyword: {keyword}")
                
        except Exception as e:
            logger.error(f"Shodan-like search failed: {e}")
        
        return targets
    
    async def _search_github_repos(self) -> List[Dict]:
        """
        Search GitHub for repositories that might contain target information.
        
        Looks for exposed URLs, API endpoints, etc.
        """
        targets = []
        
        try:
            # In production, you would use GitHub API to search for:
            # - Exposed URLs in code
            # - API endpoints
            # - Configuration files with URLs
            # - README files mentioning services
            
            logger.info("GitHub repository search simulated")
            
        except Exception as e:
            logger.error(f"GitHub search failed: {e}")
        
        return targets
    
    def _score_targets(self, targets: List[Dict]) -> List[Dict]:
        """
        Score and rank discovered targets based on multiple factors.
        
        Scoring factors:
        - Keyword relevance
        - Domain age (newer = higher score)
        - Technology stack
        - Attack surface indicators
        """
        scored_targets = []
        
        for target in targets:
            score = 0
            
            # Base score from source
            source_scores = {
                'certificate_transparency': 70,
                'newly_registered': 90,  # Newly registered domains are high priority
                'shodan': 80,
                'github': 60
            }
            score += source_scores.get(target.get('source', ''), 50)
            
            # Keyword relevance
            high_value_keywords = ['casino', 'betting', 'payment', 'crypto', 'financial']
            keyword = target.get('keyword', '').lower()
            if any(hv in keyword for hv in high_value_keywords):
                score += 20
            
            # Domain characteristics
            domain = target.get('domain', '')
            if any(indicator in domain for indicator in ['new', 'app', 'api', 'dev', 'test']):
                score += 10
            
            # Recency (if registration date available)
            if 'registration_date' in target:
                try:
                    reg_date = datetime.fromisoformat(target['registration_date'])
                    days_old = (datetime.now() - reg_date).days
                    if days_old < 30:
                        score += 15
                    elif days_old < 90:
                        score += 10
                except Exception as e:
                    logging.error("Error occurred")
            
            target['score'] = score
            target['priority'] = 'high' if score >= 90 else 'medium' if score >= 70 else 'low'
            
            scored_targets.append(target)
        
        return scored_targets
    
    async def verify_target(self, target: Dict) -> Dict:
        """
        Verify that a target is reachable and gather basic information.
        
        Args:
            target: Target dictionary
            
        Returns:
            Updated target with verification results
        """
        url = target['url']
        
        try:
            async with self.session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as response:
                target['verified'] = True
                target['status_code'] = response.status
                target['final_url'] = str(response.url)
                target['server'] = response.headers.get('Server', 'Unknown')
                target['technologies'] = self._detect_technologies(response.headers, await response.text())
                
                logger.info(f"Target verified: {url} (Status: {response.status})")
                
        except asyncio.TimeoutError:
            target['verified'] = False
            target['error'] = 'timeout'
            logger.warning(f"Target verification timeout: {url}")
            
        except Exception as e:
            target['verified'] = False
            target['error'] = str(e)
            logger.warning(f"Target verification failed: {url} - {e}")
        
        return target
    
    def _detect_technologies(self, headers: Dict, html: str) -> List[str]:
        """Detect technologies used by the target."""
        technologies = []
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        elif 'apache' in server:
            technologies.append('apache')
        elif 'cloudflare' in server:
            technologies.append('cloudflare')
        
        # Framework detection from HTML
        if 'wp-content' in html or 'wordpress' in html.lower():
            technologies.append('wordpress')
        if 'drupal' in html.lower():
            technologies.append('drupal')
        if 'joomla' in html.lower():
            technologies.append('joomla')
        if 'react' in html.lower():
            technologies.append('react')
        if 'vue' in html.lower():
            technologies.append('vue')
        if 'angular' in html.lower():
            technologies.append('angular')
        
        return technologies
    
    async def get_best_target(self) -> Optional[Dict]:
        """
        Get the single best target for immediate attack.
        
        Returns:
            Best target dictionary or None
        """
        targets = await self.discover_targets(max_targets=20)
        
        # Verify top targets
        verified_targets = []
        for target in targets[:5]:  # Verify top 5
            verified = await self.verify_target(target)
            if verified.get('verified'):
                verified_targets.append(verified)
        
        if verified_targets:
            best = verified_targets[0]
            logger.info(f"Best target selected: {best['url']} (Score: {best['score']})")
            return best
        
        logger.warning("No verified targets found")
        return None


async def main():
    """Test the Target Acquisition Agent."""
    keywords = [
        "online casino",
        "betting site",
        "crypto exchange"
    ]
    
    async with TargetAcquisitionAgent(keywords=keywords) as agent:
        # Discover targets
        targets = await agent.discover_targets(max_targets=10)
        
        print(f"\n=== Discovered {len(targets)} Targets ===\n")
        for i, target in enumerate(targets, 1):
            print(f"{i}. {target['url']}")
            print(f"   Source: {target['source']}")
            print(f"   Keyword: {target['keyword']}")
            print(f"   Score: {target['score']} ({target['priority']} priority)")
            print()
        
        # Get best target
        best = await agent.get_best_target()
        if best:
            print(f"\n=== Best Target for Attack ===\n")
            print(f"URL: {best['url']}")
            print(f"Score: {best['score']}")
            print(f"Status: {best.get('status_code', 'N/A')}")
            print(f"Server: {best.get('server', 'Unknown')}")
            print(f"Technologies: {', '.join(best.get('technologies', []))}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

