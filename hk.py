#!/usr/bin/env python3.11
"""
HK - Hacker Knowledge CLI
Powered by Manus AI via api.manus.im
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Load environment
sys.path.insert(0, '/home/ubuntu/aiprojectattack')
env_file = Path('/home/ubuntu/aiprojectattack/.env')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                
                if key in os.environ and os.environ[key] and not os.environ[key].startswith('${'):
                    continue
                
                if value.startswith('${') and value.endswith('}'):
                    var_name = value[2:-1]
                    expanded = os.environ.get(var_name, '')
                    if expanded:
                        value = expanded
                    else:
                        continue
                
                os.environ[key] = value

try:
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.live import Live
    from rich.spinner import Spinner
except ImportError:
    print("Installing dependencies...", file=sys.stderr)
    os.system("pip3 install -q openai rich >&2")
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.live import Live
    from rich.spinner import Spinner


class HK:
    """Hacker Knowledge CLI"""
    
    def __init__(self):
        self.console = Console()
        
        # OpenAI client (connects to Manus API)
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key or api_key.startswith('${'):
            self.console.print("[red]❌ OPENAI_API_KEY not set[/red]")
            sys.exit(1)
        
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4.1-mini"
        
        # History
        self.history_dir = Path.home() / '.hk_history'
        self.history_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / 'conversation.json'
        self.history = []
        
        self._load_history()
        
        # System prompt
        self.system_prompt = """คุณคือ Manus AI - AI Assistant สำหรับโปรเจค dLNk Attack Platform

**ความสามารถ:**
- ตอบคำถามเกี่ยวกับระบบ dLNk (Backend, Frontend, API, Agents, C2, Zero-Day Hunter)
- แนะนำวิธีใช้งานเครื่องมือและฟีเจอร์ต่างๆ
- อธิบายเทคนิคการโจมตีและการป้องกัน
- ช่วยเขียนและแก้ไขโค้ด
- วิเคราะห์ปัญหาและแนะนำวิธีแก้ไข
- สรุปข้อมูลและสร้างเอกสาร

**รูปแบบการตอบ:**
- ตอบเป็นภาษาไทย ชัดเจน กระชับ
- ใช้ Markdown format
- ใส่ code block สำหรับโค้ด
- ใช้ emoji เมื่อเหมาะสม
- ตอบตรงประเด็น ไม่อ้อมค้อม

**โปรเจค dLNk:**
- Backend API: 122 endpoints, PostgreSQL, Redis
- Frontend: Dashboard, Web Terminal
- AI Agents: 75 agents (98% functional)
- C2 Infrastructure: Shell Handler, Payload Generator
- Zero-Day Hunter: Deep scan, Fuzzing, ML analysis
- LLM Integration: OpenAI GPT-4.1-mini
- Self-Healing: Auto-recovery, Health monitoring
- Overall Progress: 89.6%
"""
    
    def _load_history(self):
        """โหลดประวัติ"""
        try:
            if self.history_file.exists():
                data = json.loads(self.history_file.read_text(encoding='utf-8'))
                self.history = data.get('messages', [])[-20:]  # เก็บ 20 ข้อความล่าสุด
        except:
            pass
    
    def _save_history(self):
        """บันทึกประวัติ"""
        try:
            self.history_file.write_text(json.dumps({
                'timestamp': datetime.now().isoformat(),
                'messages': self.history
            }, ensure_ascii=False, indent=2), encoding='utf-8')
        except:
            pass
    
    def banner(self):
        """แสดง banner"""
        banner_text = """
╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ██╗     ███╗   ██╗██╗  ██╗                    ║
║   ██╔══██╗██║     ████╗  ██║██║ ██╔╝                    ║
║   ██║  ██║██║     ██╔██╗ ██║█████╔╝                     ║
║   ██║  ██║██║     ██║╚██╗██║██╔═██╗                     ║
║   ██████╔╝███████╗██║ ╚████║██║  ██╗                    ║
║   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                    ║
║                                                           ║
║   HK - Hacker Knowledge                                  ║
║   Powered by Manus AI (api.manus.im)                     ║
╚═══════════════════════════════════════════════════════════╝
"""
        self.console.print(banner_text, style="bold cyan")
        
        if self.history:
            self.console.print(f"[dim]💾 โหลดประวัติ {len(self.history)} ข้อความ[/dim]\n")
        
        self.console.print("[dim]พิมพ์ 'help' สำหรับความช่วยเหลือ | 'exit' เพื่อออก[/dim]\n")
    
    def show_help(self):
        """แสดงความช่วยเหลือ"""
        help_text = """
**คำสั่ง:**
- `exit`, `quit`, `q` - ออกจากโปรแกรม
- `clear` - ล้างประวัติการสนทนา
- `history` - แสดงประวัติ 10 ข้อความล่าสุด
- `export` - ส่งออกประวัติเป็น Markdown
- `help` - แสดงความช่วยเหลือ

**ตัวอย่างการใช้งาน:**

💬 **คำถามทั่วไป:**
- "สรุปภาพรวมโปรเจค dLNk"
- "ตรวจสอบสถานะระบบ"
- "วิธีใช้งาน C2 Infrastructure"

🔧 **เทคนิค:**
- "อธิบาย SQL injection"
- "วิธีสร้าง reverse shell payload"
- "แนะนำเทคนิค privilege escalation"

💻 **โค้ด:**
- "เขียน Python script สำหรับ port scanning"
- "สร้าง exploit สำหรับ buffer overflow"
- "แก้ไข bug ในไฟล์ X"

📊 **วิเคราะห์:**
- "วิเคราะห์ช่องโหว่ของ target.com"
- "แนะนำวิธีโจมตี web application"
- "สรุปผลการสแกน"
"""
        self.console.print(Panel(Markdown(help_text), title="Help", border_style="cyan"))
    
    def show_history(self):
        """แสดงประวัติ"""
        if not self.history:
            self.console.print("[yellow]ไม่มีประวัติการสนทนา[/yellow]")
            return
        
        self.console.print("\n[bold cyan]📜 ประวัติ 10 ข้อความล่าสุด:[/bold cyan]\n")
        
        recent = self.history[-20:]  # 10 คู่ (user + assistant)
        count = 0
        for i in range(len(recent)-1, -1, -1):
            msg = recent[i]
            role = "👤 You" if msg['role'] == 'user' else "🤖 Manus"
            content = msg['content'][:80] + "..." if len(msg['content']) > 80 else msg['content']
            timestamp = msg.get('timestamp', '')
            
            self.console.print(f"[dim]{timestamp}[/dim]")
            self.console.print(f"{role}: {content}\n")
            
            count += 1
            if count >= 10:
                break
    
    def export_history(self):
        """ส่งออกประวัติ"""
        try:
            export_file = self.history_dir / f'export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
            
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write(f"# HK Conversation History\n\n")
                f.write(f"**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("---\n\n")
                
                for msg in self.history:
                    role = msg['role']
                    content = msg['content']
                    timestamp = msg.get('timestamp', '')
                    
                    if role == 'user':
                        f.write(f"## 👤 You\n\n")
                    else:
                        f.write(f"## 🤖 Manus AI\n\n")
                    
                    if timestamp:
                        f.write(f"*{timestamp}*\n\n")
                    
                    f.write(f"{content}\n\n")
                    f.write("---\n\n")
            
            self.console.print(f"[green]✅ ส่งออกประวัติไปยัง: {export_file}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]❌ Error: {e}[/red]")
    
    def chat(self, question: str):
        """สนทนากับ Manus AI"""
        # บันทึกคำถาม
        self.history.append({
            'role': 'user',
            'content': question,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        # เตรียม messages
        messages = [{'role': 'system', 'content': self.system_prompt}]
        messages.extend(self.history[-20:])  # ส่ง context 20 ข้อความล่าสุด
        
        try:
            # เรียก Manus API
            self.console.print("\n[cyan]🤖 Manus AI:[/cyan]")
            
            with Live(Spinner("dots", text="[cyan]กำลังคิด...[/cyan]"), console=self.console, transient=True):
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.7,
                    max_tokens=2000,
                    stream=False
                )
            
            answer = response.choices[0].message.content
            
            # บันทึกคำตอบ
            self.history.append({
                'role': 'assistant',
                'content': answer,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
            # แสดงคำตอบ
            try:
                self.console.print(Markdown(answer))
            except:
                self.console.print(answer)
            
            # บันทึกประวัติ
            self._save_history()
            
        except Exception as e:
            self.console.print(f"[red]❌ Error: {e}[/red]")
    
    def run(self):
        """Main loop"""
        # Set UTF-8
        if hasattr(sys.stdin, 'reconfigure'):
            sys.stdin.reconfigure(encoding='utf-8', errors='ignore')
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
        
        self.banner()
        
        while True:
            try:
                # รับคำถาม
                question = Prompt.ask("\n[bold green]You[/bold green]").strip()
                
                if not question:
                    continue
                
                # คำสั่งพิเศษ
                cmd = question.lower()
                
                if cmd in ['exit', 'quit', 'q']:
                    self.console.print("\n[cyan]👋 ขอบคุณที่ใช้งาน HK![/cyan]\n")
                    break
                
                elif cmd == 'clear':
                    self.history = []
                    self._save_history()
                    os.system('clear')
                    self.banner()
                    self.console.print("[green]✅ ล้างประวัติแล้ว[/green]")
                    continue
                
                elif cmd == 'history':
                    self.show_history()
                    continue
                
                elif cmd == 'export':
                    self.export_history()
                    continue
                
                elif cmd == 'help':
                    self.show_help()
                    continue
                
                # สนทนา
                self.chat(question)
                
            except KeyboardInterrupt:
                self.console.print("\n\n[cyan]👋 ขอบคุณที่ใช้งาน HK![/cyan]\n")
                break
            except Exception as e:
                self.console.print(f"[red]❌ Error: {e}[/red]")


if __name__ == "__main__":
    hk = HK()
    hk.run()

