#!/usr/bin/env python3.11
"""
dLNk Attack Platform - Terminal Chat CLI
Command: hk
Interactive AI assistant for terminal
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

# Load environment variables from .env
env_file = Path('/home/ubuntu/aiprojectattack/.env')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"').strip("'")

try:
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Installing required packages...")
    os.system("pip3 install -q openai rich")
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    RICH_AVAILABLE = True


class HackerKnowledge:
    """Terminal AI Assistant"""
    
    def __init__(self):
        self.console = Console()
        self.client = OpenAI()  # API key from environment
        self.model = "gpt-4.1-mini"
        self.conversation_history = []
        self.system_prompt = """คุณคือ AI Assistant สำหรับ dLNk Attack Platform - ระบบโจมตีทางไซเบอร์ขั้นสูง

คุณสามารถช่วยเหลือในเรื่อง:
- การใช้งานระบบ dLNk Attack Platform
- คำสั่ง CLI และ API
- การโจมตีและทดสอบความปลอดภัย
- การวิเคราะห์ช่องโหว่
- การเขียน exploit และ payload
- การใช้งาน C2 และ reverse shell
- Zero-day hunting และ fuzzing
- Post-exploitation techniques
- ปัญหาทางเทคนิคต่างๆ

ตอบเป็นภาษาไทยและให้คำแนะนำที่เป็นประโยชน์ ชัดเจน และปฏิบัติได้จริง
"""
    
    def show_banner(self):
        """Show welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗     ███╗   ██╗██╗  ██╗                    ║
║   ██╔══██╗██║     ████╗  ██║██║ ██╔╝                    ║
║   ██║  ██║██║     ██╔██╗ ██║█████╔╝                     ║
║   ██║  ██║██║     ██║╚██╗██║██╔═██╗                     ║
║   ██████╔╝███████╗██║ ╚████║██║  ██╗                    ║
║   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                    ║
║                                                           ║
║   Hacker Knowledge - Terminal AI Assistant               ║
║   AI-Powered Autonomous Attack System                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

พิมพ์คำถามหรือคำสั่งของคุณ
พิมพ์ 'exit', 'quit' หรือ 'q' เพื่อออก
พิมพ์ 'clear' เพื่อล้างประวัติการสนทนา
พิมพ์ 'help' เพื่อดูคำสั่งที่มี
"""
        self.console.print(banner, style="bold cyan")
    
    def show_help(self):
        """Show help message"""
        help_text = """
**คำสั่งที่ใช้ได้:**

- `exit`, `quit`, `q` - ออกจากโปรแกรม
- `clear` - ล้างประวัติการสนทนา
- `help` - แสดงความช่วยเหลือ
- `status` - ตรวจสอบสถานะระบบ
- `keys` - แสดง API Keys
- `payloads` - สร้าง reverse shell payloads
- `exploit <target>` - เริ่มโจมตี
- `scan <target>` - สแกนเป้าหมาย

**ตัวอย่างคำถาม:**

- "วิธีใช้งาน C2 listener ยังไง?"
- "สร้าง reverse shell payload สำหรับ Linux"
- "วิเคราะห์ช่องโหว่ SQL injection"
- "แนะนำวิธี privilege escalation"
- "ตรวจสอบสถานะระบบ"
"""
        self.console.print(Panel(Markdown(help_text), title="Help", border_style="green"))
    
    def chat(self, user_message: str) -> str:
        """Send message to AI"""
        try:
            # Add to history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })
            
            # Prepare messages
            messages = [
                {"role": "system", "content": self.system_prompt}
            ] + self.conversation_history
            
            # Call API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=2000
            )
            
            ai_response = response.choices[0].message.content
            
            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": ai_response
            })
            
            return ai_response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def execute_command(self, command: str) -> bool:
        """Execute special commands"""
        cmd = command.strip().lower()
        
        if cmd in ['exit', 'quit', 'q']:
            self.console.print("\n[bold cyan]👋 ขอบคุณที่ใช้งาน dLNk Attack Platform![/bold cyan]\n")
            return False
        
        elif cmd == 'clear':
            self.conversation_history = []
            os.system('clear' if os.name != 'nt' else 'cls')
            self.show_banner()
            self.console.print("[green]✓ ล้างประวัติการสนทนาแล้ว[/green]\n")
            return True
        
        elif cmd == 'help':
            self.show_help()
            return True
        
        elif cmd == 'status':
            self.check_system_status()
            return True
        
        elif cmd == 'keys':
            self.show_api_keys()
            return True
        
        elif cmd == 'payloads':
            self.generate_payloads()
            return True
        
        elif cmd.startswith('exploit '):
            target = cmd.replace('exploit ', '').strip()
            self.quick_exploit(target)
            return True
        
        elif cmd.startswith('scan '):
            target = cmd.replace('scan ', '').strip()
            self.quick_scan(target)
            return True
        
        return None
    
    def check_system_status(self):
        """Check system status"""
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=5)
            data = response.json()
            
            status_text = f"""
**System Status:**
- Status: {data.get('status', 'unknown')}
- Database: {'✓ Connected' if data.get('database') else '✗ Disconnected'}
- Version: {data.get('version', 'unknown')}
- Timestamp: {data.get('timestamp', 'unknown')}
"""
            self.console.print(Panel(Markdown(status_text), title="System Status", border_style="green"))
        except Exception as e:
            self.console.print(f"[red]❌ Error checking status: {e}[/red]")
    
    def show_api_keys(self):
        """Show API keys"""
        keys_text = """
**API Keys:**

- Admin Key: `admin_key_001`
- Web Terminal Password: `admin_key_001`

**Usage:**
```bash
curl -H "X-API-Key: admin_key_001" http://localhost:8000/api/...
```
"""
        self.console.print(Panel(Markdown(keys_text), title="API Keys", border_style="yellow"))
    
    def generate_payloads(self):
        """Generate payloads"""
        try:
            import requests
            response = requests.get(
                "http://localhost:8000/api/c2/payloads",
                headers={"X-API-Key": "admin_key_001"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                payloads_text = f"""
**Reverse Shell Payloads:**

LHOST: {data.get('lhost')}
LPORT: {data.get('lport')}

**Available Payloads:**
{', '.join(data.get('payloads', {}).keys())}

Use: `hk` and ask "แสดง bash payload" for specific payload
"""
                self.console.print(Panel(Markdown(payloads_text), title="Payloads", border_style="cyan"))
            else:
                self.console.print(f"[red]❌ Error: {response.status_code}[/red]")
        except Exception as e:
            self.console.print(f"[red]❌ Error: {e}[/red]")
    
    def quick_exploit(self, target: str):
        """Quick exploit"""
        self.console.print(f"[yellow]🎯 Starting attack on {target}...[/yellow]")
        try:
            import requests
            response = requests.post(
                "http://localhost:8000/api/v1/one-click/attack",
                headers={"X-API-Key": "admin_key_001"},
                json={"target_url": target, "attack_type": "quick_scan"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.console.print(f"[green]✓ Attack started: {data.get('attack_id')}[/green]")
                self.console.print(f"[cyan]Status: {data.get('status')}[/cyan]")
            else:
                self.console.print(f"[red]❌ Error: {response.text}[/red]")
        except Exception as e:
            self.console.print(f"[red]❌ Error: {e}[/red]")
    
    def quick_scan(self, target: str):
        """Quick scan"""
        self.console.print(f"[yellow]🔍 Scanning {target}...[/yellow]")
        self.console.print(f"[cyan]Use 'exploit {target}' to start attack[/cyan]")
    
    def run(self):
        """Main loop"""
        self.show_banner()
        
        while True:
            try:
                # Get user input
                user_input = Prompt.ask("\n[bold green]You[/bold green]").strip()
                
                if not user_input:
                    continue
                
                # Check for special commands
                cmd_result = self.execute_command(user_input)
                if cmd_result is False:
                    break
                elif cmd_result is True:
                    continue
                
                # Send to AI
                self.console.print("\n[bold cyan]AI Assistant[/bold cyan]:")
                
                with self.console.status("[cyan]Thinking...[/cyan]"):
                    response = self.chat(user_input)
                
                # Display response
                self.console.print(Markdown(response))
                
            except KeyboardInterrupt:
                self.console.print("\n\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
                break
            except Exception as e:
                self.console.print(f"\n[red]❌ Error: {e}[/red]")


def main():
    """Main entry point"""
    hk = HackerKnowledge()
    hk.run()


if __name__ == "__main__":
    main()

