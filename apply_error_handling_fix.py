#!/usr/bin/env python3
"""
Phase 2.2-2.4: แก้ไข Error Handling ทั้งหมด
"""

import os
import re
from pathlib import Path
from typing import List, Dict

def find_except_pass(directory=".") -> List[Dict]:
    """หาไฟล์ทั้งหมดที่มี except: pass"""
    issues = []
    
    for py_file in Path(directory).rglob("*.py"):
        if '__pycache__' in str(py_file) or 'venv' in str(py_file):
            continue
            
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith('except') and stripped.endswith(':'):
                    if i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line == 'pass':
                            issues.append({
                                'file': str(py_file),
                                'line': i + 2,  # 1-indexed, pass line
                                'except_line': i + 1,  # 1-indexed, except line
                                'except_text': stripped
                            })
        except Exception as e:
            print(f"Error reading {py_file}: {e}")
    
    return issues

def fix_file(filepath: str, issues: List[Dict]) -> bool:
    """แก้ไขไฟล์ทั้งหมด"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # เรียงจากบรรทัดท้ายสุดไปหน้าสุด เพื่อไม่ให้ line number เปลี่ยน
        issues_sorted = sorted(issues, key=lambda x: x['line'], reverse=True)
        
        modified = False
        for issue in issues_sorted:
            pass_line_idx = issue['line'] - 1  # Convert to 0-indexed
            except_line_idx = issue['except_line'] - 1
            
            if pass_line_idx >= len(lines):
                continue
            
            # ตรวจสอบว่ายังเป็น pass อยู่หรือไม่
            if lines[pass_line_idx].strip() != 'pass':
                continue
            
            # หา indent
            pass_indent = len(lines[pass_line_idx]) - len(lines[pass_line_idx].lstrip())
            
            # ดูว่ามี logging import หรือไม่
            has_logging = any('import logging' in line or 'from logging import' in line for line in lines)
            has_log = any(re.search(r'\blog\s*=', line) for line in lines)
            
            # สร้าง error handling
            except_text = issue['except_text']
            
            if ' as ' in except_text:
                # มีตัวแปร exception
                var_name = except_text.split(' as ')[-1].strip(':').strip()
                if has_logging or has_log:
                    new_line = ' ' * pass_indent + f'logging.error(f"Error: {{{var_name}}}")\n'
                else:
                    new_line = ' ' * pass_indent + f'print(f"Error: {{{var_name}}}")\n'
            else:
                # ไม่มีตัวแปร exception
                if has_logging or has_log:
                    new_line = ' ' * pass_indent + 'logging.error("Error occurred")\n'
                else:
                    new_line = ' ' * pass_indent + 'print("Error occurred")\n'
            
            lines[pass_line_idx] = new_line
            modified = True
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True
        
        return False
    except Exception as e:
        print(f"❌ Error fixing {filepath}: {e}")
        return False

if __name__ == "__main__":
    print("🔧 เริ่มแก้ไข Error Handling ทั้งหมด...\n")
    
    issues = find_except_pass()
    
    # จัดกลุ่มตามไฟล์
    by_file = {}
    for issue in issues:
        filepath = issue['file']
        if filepath not in by_file:
            by_file[filepath] = []
        by_file[filepath].append(issue)
    
    print(f"📊 พบ {len(issues)} จุดใน {len(by_file)} ไฟล์\n")
    
    # แก้ไขทีละไฟล์
    fixed_count = 0
    error_count = 0
    
    for filepath, file_issues in sorted(by_file.items()):
        if fix_file(filepath, file_issues):
            print(f"✅ {filepath}: แก้ไข {len(file_issues)} จุด")
            fixed_count += 1
        else:
            print(f"⚠️  {filepath}: ไม่มีการเปลี่ยนแปลง")
            error_count += 1
    
    print(f"\n✅ เสร็จสิ้น!")
    print(f"   แก้ไขสำเร็จ: {fixed_count} ไฟล์")
    print(f"   ไม่มีการเปลี่ยนแปลง: {error_count} ไฟล์")
