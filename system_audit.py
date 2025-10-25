#!/usr/bin/env python3
"""
dLNk Attack Platform - Full System Audit Script
ตรวจสอบปัญหาทั้งหมดในระบบ
"""

import os
import sys
import ast
import json
from pathlib import Path
from typing import List, Dict, Any
import re

class SystemAuditor:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.issues = []
        self.stats = {
            "total_files": 0,
            "total_issues": 0,
            "critical": 0,
            "warning": 0,
            "info": 0
        }
    
    def add_issue(self, severity: str, category: str, file: str, line: int, message: str, suggestion: str = ""):
        """เพิ่มปัญหาที่พบ"""
        self.issues.append({
            "severity": severity,  # critical, warning, info
            "category": category,
            "file": str(file),
            "line": line,
            "message": message,
            "suggestion": suggestion
        })
        self.stats["total_issues"] += 1
        self.stats[severity] += 1
    
    def check_imports(self, file_path: Path):
        """ตรวจสอบ imports ที่อาจมีปัญหา"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            # ตรวจสอบ import ที่อาจมีปัญหา
            for i, line in enumerate(lines, 1):
                # ตรวจสอบ relative imports ที่ไม่ถูกต้อง
                if re.match(r'^from \.\. import', line) or re.match(r'^from \.\.\. import', line):
                    self.add_issue(
                        "warning",
                        "imports",
                        file_path,
                        i,
                        f"Relative import อาจทำให้เกิดปัญหา: {line.strip()}",
                        "ใช้ absolute imports แทน"
                    )
                
                # ตรวจสอบ import * ที่ไม่ควรใช้
                if re.search(r'import \*', line):
                    self.add_issue(
                        "warning",
                        "imports",
                        file_path,
                        i,
                        f"ไม่ควรใช้ import *: {line.strip()}",
                        "ระบุชื่อ function/class ที่ต้องการ import"
                    )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_database_usage(self, file_path: Path):
        """ตรวจสอบการใช้งาน Database"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # ตรวจสอบ Database() ที่ไม่ได้ connect
            for i, line in enumerate(lines, 1):
                if re.search(r'^\s*db\s*=\s*Database\(\)', line) and 'main.py' not in str(file_path):
                    # ตรวจสอบว่ามี set_dependencies หรือไม่
                    if 'def set_dependencies' not in content:
                        self.add_issue(
                            "critical",
                            "database",
                            file_path,
                            i,
                            "สร้าง Database() instance โดยไม่ได้ connect",
                            "ใช้ dependency injection จาก main.py"
                        )
                
                # ตรวจสอบการใช้ self.pool โดยตรง
                if re.search(r'self\.pool\.acquire\(\)', line):
                    # ตรวจสอบว่ามี None check หรือไม่
                    prev_lines = '\n'.join(lines[max(0, i-5):i])
                    if 'if self.pool' not in prev_lines and 'if not self.pool' not in prev_lines:
                        self.add_issue(
                            "warning",
                            "database",
                            file_path,
                            i,
                            "ใช้ self.pool โดยไม่ตรวจสอบ None",
                            "เพิ่ม None check ก่อนใช้งาน"
                        )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_environment_variables(self, file_path: Path):
        """ตรวจสอบการใช้ environment variables"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # ตรวจสอบ hardcoded paths
                if re.search(r'["\']/(home|mnt|Users|C:)/', line) and 'WORKSPACE_DIR' not in line:
                    # ข้าม fix_critical_issues.py และบรรทัดที่เป็น regex pattern
                    if 'fix_critical_issues.py' in str(file_path) or '(r\'' in line or '(r"' in line:
                        continue
                    if not line.strip().startswith('#'):
                        self.add_issue(
                            "critical",
                            "config",
                            file_path,
                            i,
                            f"พบ hardcoded path: {line.strip()[:80]}",
                            "ใช้ environment variable แทน"
                        )
                
                # ตรวจสอบ os.getenv ที่ไม่มี default value
                if re.search(r'os\.getenv\(["\'][^"\']+["\']\)', line):
                    if ', ' not in line or ')' == line.strip()[-1]:
                        self.add_issue(
                            "warning",
                            "config",
                            file_path,
                            i,
                            "os.getenv() ไม่มี default value",
                            "เพิ่ม default value เพื่อป้องกัน None"
                        )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_error_handling(self, file_path: Path):
        """ตรวจสอบ error handling"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            in_try_block = False
            try_line = 0
            
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                
                if stripped.startswith('try:'):
                    in_try_block = True
                    try_line = i
                
                if in_try_block and stripped.startswith('except:'):
                    self.add_issue(
                        "warning",
                        "error_handling",
                        file_path,
                        i,
                        "ใช้ bare except ไม่ระบุ exception type",
                        "ระบุ exception type ที่ต้องการจับ"
                    )
                
                if in_try_block and (stripped.startswith('except ') or stripped.startswith('finally:')):
                    in_try_block = False
                
                # ตรวจสอบ pass ใน except block
                if stripped == 'pass' and i > 0:
                    prev_line = lines[i-2].strip() if i >= 2 else ""
                    if prev_line.startswith('except'):
                        self.add_issue(
                            "warning",
                            "error_handling",
                            file_path,
                            i,
                            "except block ว่างเปล่า (pass only)",
                            "เพิ่ม logging หรือ error handling"
                        )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_async_await(self, file_path: Path):
        """ตรวจสอบการใช้ async/await"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # ตรวจสอบ async function ที่ไม่มี await
                if re.match(r'^\s*async def ', line):
                    # ดูใน function body
                    func_content = []
                    indent_level = len(line) - len(line.lstrip())
                    for j in range(i, min(i+50, len(lines))):
                        if j < len(lines):
                            next_line = lines[j]
                            next_indent = len(next_line) - len(next_line.lstrip())
                            if next_indent <= indent_level and next_line.strip() and j > i:
                                break
                            func_content.append(next_line)
                    
                    func_text = '\n'.join(func_content)
                    if 'await ' not in func_text and 'async for' not in func_text:
                        self.add_issue(
                            "info",
                            "async",
                            file_path,
                            i,
                            f"async function ไม่มี await: {line.strip()[:60]}",
                            "ตรวจสอบว่าควรเป็น async หรือไม่"
                        )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_llm_integration(self, file_path: Path):
        """ตรวจสอบ LLM integration"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # ตรวจสอบ API key ที่อาจ hardcode
                if re.search(r'(api_key|API_KEY)\s*=\s*["\'][^"\']{20,}["\']', line):
                    if 'os.getenv' not in line and 'config' not in line.lower():
                        self.add_issue(
                            "critical",
                            "security",
                            file_path,
                            i,
                            "พบ API key ที่อาจ hardcode",
                            "ใช้ environment variable"
                        )
                
                # ตรวจสอบ timeout ใน LLM calls
                if 'openai' in content.lower() or 'llm' in content.lower():
                    if re.search(r'\.create\(|\.generate\(|\.chat\(', line):
                        if 'timeout' not in line and 'timeout=' not in content[max(0, content.find(line)-200):content.find(line)+200]:
                            self.add_issue(
                                "warning",
                                "llm",
                                file_path,
                                i,
                                "LLM call ไม่มี timeout",
                                "เพิ่ม timeout parameter"
                            )
        except Exception as e:
            print(f"Error: {e}")
    
    def check_file_operations(self, file_path: Path):
        """ตรวจสอบการทำงานกับไฟล์"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # ตรวจสอบ open() ที่ไม่ใช้ with statement
                if re.search(r'=\s*open\(', line) and 'with ' not in line:
                    self.add_issue(
                        "warning",
                        "file_operations",
                        file_path,
                        i,
                        "ใช้ open() โดยไม่ใช้ with statement",
                        "ใช้ with open() เพื่อ auto close"
                    )
                
                # ตรวจสอบ os.makedirs ที่ไม่มี exist_ok
                if re.search(r'os\.makedirs\([^)]+\)', line):
                    if 'exist_ok' not in line:
                        self.add_issue(
                            "warning",
                            "file_operations",
                            file_path,
                            i,
                            "os.makedirs() ไม่มี exist_ok=True",
                            "เพิ่ม exist_ok=True เพื่อป้องกัน error"
                        )
        except Exception as e:
            print(f"Error: {e}")
    
    def audit_file(self, file_path: Path):
        """ตรวจสอบไฟล์เดียว"""
        self.stats["total_files"] += 1
        
        # ข้าม test files และ __init__.py ที่ว่างเปล่า
        if '__pycache__' in str(file_path) or 'venv' in str(file_path):
            return
        
        if file_path.stat().st_size == 0:
            return
        
        # รันการตรวจสอบทั้งหมด
        self.check_imports(file_path)
        self.check_database_usage(file_path)
        self.check_environment_variables(file_path)
        self.check_error_handling(file_path)
        self.check_async_await(file_path)
        self.check_llm_integration(file_path)
        self.check_file_operations(file_path)
    
    def audit_project(self):
        """ตรวจสอบทั้งโปรเจค"""
        print("🔍 เริ่มตรวจสอบโปรเจค dLNk Attack Platform...")
        print()
        
        # หาไฟล์ Python ทั้งหมด
        python_files = list(self.project_root.rglob("*.py"))
        python_files = [f for f in python_files if '__pycache__' not in str(f) and 'venv' not in str(f)]
        
        print(f"📁 พบไฟล์ Python ทั้งหมด: {len(python_files)} ไฟล์")
        print()
        
        # ตรวจสอบแต่ละไฟล์
        for i, file_path in enumerate(python_files, 1):
            if i % 50 == 0:
                print(f"⏳ ตรวจสอบแล้ว {i}/{len(python_files)} ไฟล์...")
            self.audit_file(file_path)
        
        print()
        print("✅ ตรวจสอบเสร็จสิ้น!")
        print()
    
    def generate_report(self) -> str:
        """สร้างรายงาน"""
        report = []
        report.append("=" * 80)
        report.append("dLNk Attack Platform - System Audit Report")
        report.append("=" * 80)
        report.append("")
        
        # สถิติ
        report.append("📊 สถิติ")
        report.append("-" * 80)
        report.append(f"ไฟล์ทั้งหมด: {self.stats['total_files']}")
        report.append(f"ปัญหาทั้งหมด: {self.stats['total_issues']}")
        report.append(f"  🔴 Critical: {self.stats['critical']}")
        report.append(f"  🟡 Warning: {self.stats['warning']}")
        report.append(f"  🔵 Info: {self.stats['info']}")
        report.append("")
        
        # จัดกลุ่มปัญหาตาม category
        issues_by_category = {}
        for issue in self.issues:
            cat = issue['category']
            if cat not in issues_by_category:
                issues_by_category[cat] = []
            issues_by_category[cat].append(issue)
        
        # แสดงปัญหาแต่ละ category
        for category, issues in sorted(issues_by_category.items()):
            report.append(f"📁 {category.upper()}")
            report.append("-" * 80)
            
            # จัดกลุ่มตาม severity
            critical = [i for i in issues if i['severity'] == 'critical']
            warning = [i for i in issues if i['severity'] == 'warning']
            info = [i for i in issues if i['severity'] == 'info']
            
            if critical:
                report.append(f"\n🔴 Critical Issues: {len(critical)}")
                for issue in critical[:10]:  # แสดงแค่ 10 อันแรก
                    report.append(f"  📄 {issue['file']}:{issue['line']}")
                    report.append(f"     {issue['message']}")
                    if issue['suggestion']:
                        report.append(f"     💡 {issue['suggestion']}")
                    report.append("")
                if len(critical) > 10:
                    report.append(f"  ... และอีก {len(critical) - 10} issues")
                    report.append("")
            
            if warning:
                report.append(f"\n🟡 Warning Issues: {len(warning)}")
                for issue in warning[:5]:  # แสดงแค่ 5 อันแรก
                    report.append(f"  📄 {issue['file']}:{issue['line']}")
                    report.append(f"     {issue['message']}")
                    report.append("")
                if len(warning) > 5:
                    report.append(f"  ... และอีก {len(warning) - 5} issues")
                    report.append("")
            
            report.append("")
        
        # สรุป
        report.append("=" * 80)
        report.append("📋 สรุป")
        report.append("=" * 80)
        
        if self.stats['critical'] > 0:
            report.append(f"⚠️  พบปัญหา Critical {self.stats['critical']} จุด ต้องแก้ไขก่อนใช้งาน")
        
        if self.stats['warning'] > 0:
            report.append(f"⚠️  พบปัญหา Warning {self.stats['warning']} จุด ควรแก้ไขเพื่อความมั่นคง")
        
        if self.stats['total_issues'] == 0:
            report.append("✅ ไม่พบปัญหา! ระบบพร้อมใช้งาน")
        
        report.append("")
        report.append("=" * 80)
        
        return '\n'.join(report)
    
    def save_json_report(self, output_file: str = "audit_report.json"):
        """บันทึกรายงานเป็น JSON"""
        report_data = {
            "stats": self.stats,
            "issues": self.issues
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 บันทึกรายงาน JSON: {output_file}")


if __name__ == "__main__":
    auditor = SystemAuditor(".")
    auditor.audit_project()
    
    # สร้างรายงาน
    report = auditor.generate_report()
    print(report)
    
    # บันทึกรายงาน
    with open("AUDIT_REPORT.txt", "w", encoding="utf-8") as f:
        f.write(report)
    
    auditor.save_json_report("audit_report.json")
    
    print()
    print("📄 รายงานถูกบันทึกที่: AUDIT_REPORT.txt และ audit_report.json")

