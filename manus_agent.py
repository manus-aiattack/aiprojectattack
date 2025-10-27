#!/usr/bin/env python3.11
"""
Manus AI Agent - Background service to answer hk questions
Runs in sandbox and uses OpenAI API to answer questions automatically
"""

import os
import sys
import json
import time
import signal
from pathlib import Path
from datetime import datetime

# Load environment
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

from openai import OpenAI


class ManusAgent:
    """Background AI agent to answer hk questions"""
    
    def __init__(self):
        self.client = OpenAI()
        self.model = "gpt-4.1-mini"
        
        # Communication directory
        self.comm_dir = Path('/tmp/hk_comm')
        self.comm_dir.mkdir(exist_ok=True)
        
        self.question_file = self.comm_dir / 'question.txt'
        self.answer_file = self.comm_dir / 'answer.txt'
        self.lock_file = self.comm_dir / 'lock'
        
        # Log file
        self.log_file = Path('/tmp/manus_agent.log')
        
        # System prompt
        self.system_prompt = """คุณคือ Manus AI - AI Assistant สำหรับโปรเจค dLNk Attack Platform

คุณสามารถ:
- ตอบคำถามเกี่ยวกับระบบ dLNk
- แนะนำวิธีใช้งาน
- อธิบายเทคนิคการโจมตี
- ช่วยเขียนโค้ด
- วิเคราะห์ปัญหา
- แนะนำวิธีแก้ไข

ตอบเป็นภาษาไทย ชัดเจน กระชับ และเป็นมิตร
ใช้ Markdown format สำหรับการจัดรูปแบบ
"""
        
        self.running = True
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
    
    def log(self, message):
        """Write to log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def stop(self, signum, frame):
        """Stop agent"""
        self.log("Stopping Manus Agent...")
        self.running = False
        sys.exit(0)
    
    def answer_question(self, question: str) -> str:
        """Answer question using OpenAI"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": question}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            answer = response.choices[0].message.content
            return answer
            
        except Exception as e:
            self.log(f"Error answering question: {e}")
            return f"❌ Error: {str(e)}"
    
    def run(self):
        """Main loop - watch for questions"""
        self.log("Manus Agent started")
        print("🤖 Manus AI Agent running...")
        print(f"📁 Watching: {self.question_file}")
        print(f"📝 Log: {self.log_file}")
        print("Press Ctrl+C to stop\n")
        
        while self.running:
            try:
                # Check for new question
                if self.question_file.exists() and not self.lock_file.exists():
                    # Lock
                    self.lock_file.touch()
                    
                    # Read question
                    question = self.question_file.read_text(encoding='utf-8').strip()
                    
                    if question:
                        self.log(f"Question: {question[:100]}...")
                        print(f"\n📥 Question: {question[:100]}...")
                        
                        # Answer
                        print("🤔 Thinking...")
                        answer = self.answer_question(question)
                        
                        # Write answer
                        self.answer_file.write_text(answer, encoding='utf-8')
                        
                        self.log(f"Answer: {answer[:100]}...")
                        print(f"✅ Answered: {answer[:100]}...\n")
                    
                    # Clean up
                    self.question_file.unlink()
                    self.lock_file.unlink()
                
                # Sleep
                time.sleep(0.5)
                
            except Exception as e:
                self.log(f"Error in main loop: {e}")
                if self.lock_file.exists():
                    self.lock_file.unlink()
                time.sleep(1)


if __name__ == "__main__":
    agent = ManusAgent()
    agent.run()

