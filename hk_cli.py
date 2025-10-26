#!/usr/bin/env python3.11
"""
dLNk Attack Platform - Full AI CLI Assistant
Command: hk
Full-featured AI assistant with file operations, shell commands, and real-time status
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

# Load environment variables from .env (but don't override existing ones)
env_file = Path('/home/ubuntu/aiprojectattack/.env')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                
                # Skip if already set in environment (system env takes priority)
                if key in os.environ and os.environ[key] and not os.environ[key].startswith('${'):
                    continue
                
                # Expand environment variables in value (e.g., ${VAR})
                if value.startswith('${') and value.endswith('}'):
                    var_name = value[2:-1]
                    expanded = os.environ.get(var_name, '')
                    if expanded:
                        value = expanded
                    else:
                        # Try to get from system
                        continue
                
                os.environ[key] = value

try:
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.spinner import Spinner
    RICH_AVAILABLE = True
except ImportError:
    print("Installing required packages...")
    os.system("pip3 install -q openai rich")
    from openai import OpenAI
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.spinner import Spinner
    RICH_AVAILABLE = True


class FullAIAssistant:
    """Full-featured AI Assistant with tool use capabilities"""
    
    def __init__(self):
        self.console = Console()
        
        # Check API key
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key or api_key.startswith('${'):
            self.console.print("[red]❌ Error: OPENAI_API_KEY not set properly[/red]")
            self.console.print(f"[yellow]Current value: {api_key}[/yellow]")
            self.console.print("[cyan]Please set OPENAI_API_KEY environment variable[/cyan]")
            sys.exit(1)
        
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4.1-mini"
        self.conversation_history = []
        self.working_dir = Path.cwd()
        
        # History file
        self.history_dir = Path.home() / '.hk_history'
        self.history_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / 'conversation.json'
        
        # Load previous history
        self._load_history()
        
        self.system_prompt = """คุณคือ AI Assistant แบบเต็มรูปแบบที่สามารถ:

1. **พูดคุยเรื่องอะไรก็ได้** - ไม่จำกัดหัวข้อ
2. **สร้างและแก้ไขไฟล์** - เขียนโค้ด, สร้างเอกสาร, แก้ไข config
3. **รันคำสั่ง shell** - execute commands, ติดตั้ง packages, จัดการ services
4. **Git operations** - commit, push, pull, branch
5. **ตรวจสอบระบบ** - ดูสถานะ, logs, processes
6. **วิเคราะห์และแก้ปัญหา** - debug code, แก้ error, optimize

เมื่อต้องการทำงานที่ต้องใช้ tools (สร้างไฟล์, รันคำสั่ง) ให้ตอบในรูปแบบ JSON:

```json
{
  "action": "create_file|edit_file|run_command|read_file",
  "path": "/path/to/file",
  "content": "file content",
  "command": "shell command",
  "explanation": "คำอธิบายว่ากำลังทำอะไร"
}
```

สำหรับคำถามทั่วไป ตอบเป็นข้อความธรรมดา

ตอบเป็นภาษาไทยและให้คำแนะนำที่ชัดเจน เป็นมิตร และใช้งานได้จริง
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
║   Full AI Assistant - Powered by OpenAI                  ║
║   Talk, Code, Execute - All in Terminal                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

💬 พูดคุยเรื่องอะไรก็ได้ | 📝 สร้างและแก้ไขไฟล์ | ⚡ รันคำสั่ง shell

พิมพ์ 'exit' เพื่อออก | 'clear' เพื่อล้างประวัติ | 'help' สำหรับความช่วยเหลือ
"""
        self.console.print(banner, style="bold cyan")
    
    def _load_history(self):
        """Load conversation history from file"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Load last 20 messages to keep context
                    self.conversation_history = data.get('messages', [])[-20:]
                    if self.conversation_history:
                        self.console.print(f"[dim]โหลดประวัติการสนทนา {len(self.conversation_history)} ข้อความ[/dim]")
        except Exception as e:
            self.console.print(f"[dim]ไม่สามารถโหลดประวัติ: {e}[/dim]")
    
    def _save_history(self):
        """Save conversation history to file"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'messages': self.conversation_history
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.console.print(f"[dim]ไม่สามารถบันทึกประวัติ: {e}[/dim]")
    
    def export_history(self):
        """Export history to markdown"""
        try:
            export_file = self.history_dir / f'export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
            
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write(f"# HK Conversation History\n\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("---\n\n")
                
                for msg in self.conversation_history:
                    role = msg['role']
                    content = msg['content']
                    
                    if role == 'user':
                        f.write(f"## 👤 You\n\n{content}\n\n")
                    elif role == 'assistant':
                        f.write(f"## 🤖 AI Assistant\n\n{content}\n\n")
                    
                    f.write("---\n\n")
            
            self.console.print(f"[green]✓ ส่งออกประวัติไปยัง: {export_file}[/green]")
            return str(export_file)
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return None
    
    def show_history(self, limit=10):
        """Show recent conversation history"""
        if not self.conversation_history:
            self.console.print("[yellow]ไม่มีประวัติการสนทนา[/yellow]")
            return
        
        self.console.print(f"\n[bold cyan]ประวัติการสนทนา (ล่าสุด {limit} ข้อความ)[/bold cyan]\n")
        
        recent = self.conversation_history[-limit:]
        for i, msg in enumerate(recent, 1):
            role = "👤 You" if msg['role'] == 'user' else "🤖 AI"
            content = msg['content'][:100] + "..." if len(msg['content']) > 100 else msg['content']
            self.console.print(f"{i}. {role}: {content}")
        
        self.console.print()
    
    def show_help(self):
        """Show help message"""
        help_text = """
**คำสั่งพิเศษ:**

- `exit`, `quit`, `q` - ออกจากโปรแกรม
- `clear` - ล้างประวัติการสนทนา
- `help` - แสดงความช่วยเหลือ
- `history` - แสดงประวัติการสนทนา
- `export` - ส่งออกประวัติเป็น Markdown
- `pwd` - แสดง working directory
- `cd <path>` - เปลี่ยน working directory

**ตัวอย่างการใช้งาน:**

**💬 พูดคุยทั่วไป:**
- "อธิบาย SQL injection ให้หน่อย"
- "วิธีใช้ Docker คืออะไร"
- "แนะนำหนังสือเกี่ยวกับ security"

**📝 สร้างและแก้ไขไฟล์:**
- "สร้างไฟล์ test.py ที่ print hello world"
- "แก้ไข config.json เพิ่ม timeout เป็น 30"
- "เขียน script Python สำหรับ scan ports"

**⚡ รันคำสั่ง:**
- "ตรวจสอบ process ที่ทำงานอยู่"
- "ติดตั้ง package requests"
- "restart service dlnk-platform"

**🔧 Git operations:**
- "commit และ push ไฟล์ทั้งหมด"
- "สร้าง branch ใหม่ชื่อ feature-x"
- "ดู git log"

**🎯 ระบบ dLNk:**
- "ตรวจสอบสถานะระบบ"
- "สร้าง reverse shell payload"
- "เริ่มโจมตี target.com"
"""
        self.console.print(Panel(Markdown(help_text), title="Help", border_style="green"))
    
    def chat(self, user_message: str) -> dict:
        """Send message to AI and get response"""
        try:
            # Clean message
            user_message = user_message.encode('utf-8', errors='ignore').decode('utf-8')
            
            # Add to history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })
            
            # Prepare messages
            messages = [
                {"role": "system", "content": self.system_prompt}
            ] + self.conversation_history
            
            # Call API with streaming
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=3000,
                stream=True
            )
            
            # Collect streaming response
            full_response = ""
            for chunk in response:
                if chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
            
            # Clean response
            if full_response:
                full_response = full_response.encode('utf-8', errors='ignore').decode('utf-8')
            
            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": full_response
            })
            
            # Save history after each exchange
            self._save_history()
            
            # Try to parse as JSON (tool use)
            try:
                if full_response.strip().startswith('{') and full_response.strip().endswith('}'):
                    # Extract JSON from markdown code block if present
                    if '```json' in full_response:
                        json_str = full_response.split('```json')[1].split('```')[0].strip()
                    elif '```' in full_response:
                        json_str = full_response.split('```')[1].split('```')[0].strip()
                    else:
                        json_str = full_response.strip()
                    
                    action_data = json.loads(json_str)
                    return {"type": "action", "data": action_data, "raw": full_response}
            except:
                pass
            
            return {"type": "message", "content": full_response}
            
        except Exception as e:
            import traceback
            error_msg = f"❌ Error: {str(e)}"
            self.console.print(f"[red]{error_msg}[/red]")
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return {"type": "error", "content": error_msg}
    
    def execute_action(self, action_data: dict):
        """Execute tool action"""
        action = action_data.get("action")
        explanation = action_data.get("explanation", "กำลังดำเนินการ...")
        
        self.console.print(f"\n[yellow]⚡ {explanation}[/yellow]")
        
        if action == "create_file":
            return self._create_file(action_data)
        elif action == "edit_file":
            return self._edit_file(action_data)
        elif action == "run_command":
            return self._run_command(action_data)
        elif action == "read_file":
            return self._read_file(action_data)
        else:
            return {"success": False, "error": f"Unknown action: {action}"}
    
    def _create_file(self, data: dict) -> dict:
        """Create a file"""
        try:
            path = Path(data.get("path"))
            content = data.get("content", "")
            
            # Create parent directories
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            path.write_text(content, encoding='utf-8')
            
            self.console.print(f"[green]✓ สร้างไฟล์: {path}[/green]")
            
            # Show file content
            syntax = Syntax(content, "python" if path.suffix == ".py" else "text", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title=str(path), border_style="green"))
            
            return {"success": True, "path": str(path)}
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return {"success": False, "error": str(e)}
    
    def _edit_file(self, data: dict) -> dict:
        """Edit a file"""
        try:
            path = Path(data.get("path"))
            
            if not path.exists():
                return {"success": False, "error": "File not found"}
            
            # Read current content
            current = path.read_text(encoding='utf-8')
            
            # Apply changes (simple replace for now)
            new_content = data.get("content", current)
            
            # Write file
            path.write_text(new_content, encoding='utf-8')
            
            self.console.print(f"[green]✓ แก้ไขไฟล์: {path}[/green]")
            
            return {"success": True, "path": str(path)}
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return {"success": False, "error": str(e)}
    
    def _run_command(self, data: dict) -> dict:
        """Run shell command"""
        try:
            command = data.get("command")
            
            self.console.print(f"[cyan]$ {command}[/cyan]")
            
            # Run command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Show output
            if result.stdout:
                self.console.print(result.stdout)
            
            if result.stderr:
                self.console.print(f"[yellow]{result.stderr}[/yellow]")
            
            if result.returncode == 0:
                self.console.print(f"[green]✓ Command completed[/green]")
            else:
                self.console.print(f"[red]✗ Command failed (exit code: {result.returncode})[/red]")
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return {"success": False, "error": str(e)}
    
    def _read_file(self, data: dict) -> dict:
        """Read a file"""
        try:
            path = Path(data.get("path"))
            
            if not path.exists():
                return {"success": False, "error": "File not found"}
            
            content = path.read_text(encoding='utf-8')
            
            # Show file content
            syntax = Syntax(content, "python" if path.suffix == ".py" else "text", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title=str(path), border_style="cyan"))
            
            return {"success": True, "content": content}
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return {"success": False, "error": str(e)}
    
    def execute_command(self, command: str) -> bool:
        """Execute special commands"""
        cmd = command.strip().lower()
        
        if cmd in ['exit', 'quit', 'q']:
            self.console.print("\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
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
        
        elif cmd == 'history':
            self.show_history()
            return True
        
        elif cmd == 'export':
            self.export_history()
            return True
        
        elif cmd == 'pwd':
            self.console.print(f"[cyan]Working directory: {self.working_dir}[/cyan]")
            return True
        
        elif cmd.startswith('cd '):
            new_dir = cmd.replace('cd ', '').strip()
            try:
                self.working_dir = Path(new_dir).resolve()
                os.chdir(self.working_dir)
                self.console.print(f"[green]✓ Changed to: {self.working_dir}[/green]")
            except Exception as e:
                self.console.print(f"[red]✗ Error: {e}[/red]")
            return True
        
        return None
    
    def run(self):
        """Main loop"""
        # Set UTF-8 encoding
        if hasattr(sys.stdin, 'reconfigure'):
            sys.stdin.reconfigure(encoding='utf-8', errors='ignore')
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
        
        self.show_banner()
        
        while True:
            try:
                # Get user input
                user_input = Prompt.ask("\n[bold green]You[/bold green]").strip()
                
                if not user_input:
                    continue
                
                # Clean input
                user_input = user_input.encode('utf-8', errors='ignore').decode('utf-8')
                
                # Check for special commands
                cmd_result = self.execute_command(user_input)
                if cmd_result is False:
                    break
                elif cmd_result is True:
                    continue
                
                # Show thinking status
                self.console.print("\n[bold cyan]AI Assistant[/bold cyan]:")
                
                with self.console.status("[cyan]🤔 กำลังคิด...[/cyan]", spinner="dots"):
                    response = self.chat(user_input)
                
                # Handle response
                if response["type"] == "action":
                    # Execute action
                    result = self.execute_action(response["data"])
                    
                    # Show any additional explanation
                    if "raw" in response and response["raw"] != json.dumps(response["data"]):
                        self.console.print(Markdown(response["raw"]))
                
                elif response["type"] == "message":
                    # Display message
                    try:
                        self.console.print(Markdown(response["content"]))
                    except Exception:
                        self.console.print(response["content"])
                
                elif response["type"] == "error":
                    self.console.print(f"[red]{response['content']}[/red]")
                
            except KeyboardInterrupt:
                self.console.print("\n\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
                break
            except Exception as e:
                import traceback
                self.console.print(f"\n[red]❌ Error: {e}[/red]")
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    """Main entry point"""
    assistant = FullAIAssistant()
    assistant.run()


if __name__ == "__main__":
    main()

