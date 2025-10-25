#!/usr/bin/env python3
"""
Phase 2: แก้ไข Error Handling
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Tuple

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
                # ตรวจสอบว่าเป็น except block
                if stripped.startswith('except') and stripped.endswith(':'):
                    # ตรวจสอบบรรทัดถัดไป
                    if i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line == 'pass':
                            issues.append({
                                'file': str(py_file),
                                'line': i + 1,  # line number (1-indexed)
                                'except_line': i,
                                'context': ''.join(lines[max(0, i-2):min(len(lines), i+3)])
                            })
        except Exception as e:
            print(f"Error reading {py_file}: {e}")
    
    return issues

def fix_except_pass(filepath: str, except_line: int, pass_line: int) -> bool:
    """แก้ไข except: pass ในไฟล์"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        if pass_line >= len(lines):
            return False
        
        # หา indent ของ pass
        pass_indent = len(lines[pass_line]) - len(lines[pass_line].lstrip())
        
        # ดึง exception type จากบรรทัด except
        except_line_text = lines[except_line].strip()
        
        # สร้าง error handling ใหม่
        new_lines = []
        if 'Exception as e' in except_line_text or 'Exception' in except_line_text:
            new_lines.append(' ' * pass_indent + 'log.error(f"Error: {e}")\n')
        else:
            new_lines.append(' ' * pass_indent + 'log.error("Error occurred")\n')
        
        # แทนที่ pass
        lines[pass_line] = ''.join(new_lines)
        
        # เขียนกลับ
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False

if __name__ == "__main__":
    print("🔍 สแกนหา except: pass ทั้งหมด...")
    issues = find_except_pass()
    
    print(f"\n📊 พบ {len(issues)} จุด")
    
    # จัดกลุ่มตามไฟล์
    by_file = {}
    for issue in issues:
        filepath = issue['file']
        if filepath not in by_file:
            by_file[filepath] = []
        by_file[filepath].append(issue)
    
    # แสดงรายการ
    print(f"\n📁 พบใน {len(by_file)} ไฟล์:\n")
    
    # จัดกลุ่มตามความสำคัญ
    critical_files = []
    medium_files = []
    low_files = []
    
    for filepath, file_issues in sorted(by_file.items()):
        if any(x in filepath for x in ['agents/', 'core/', 'data_exfiltration/']):
            critical_files.append((filepath, file_issues))
        elif any(x in filepath for x in ['api/', 'advanced_agents/']):
            medium_files.append((filepath, file_issues))
        else:
            low_files.append((filepath, file_issues))
    
    print(f"🔴 Critical Files ({len(critical_files)} ไฟล์, {sum(len(f[1]) for f in critical_files)} จุด):")
    for filepath, file_issues in critical_files[:10]:
        print(f"   {filepath}: {len(file_issues)} จุด")
    if len(critical_files) > 10:
        print(f"   ... และอีก {len(critical_files) - 10} ไฟล์")
    
    print(f"\n🟡 Medium Files ({len(medium_files)} ไฟล์, {sum(len(f[1]) for f in medium_files)} จุด):")
    for filepath, file_issues in medium_files[:10]:
        print(f"   {filepath}: {len(file_issues)} จุด")
    if len(medium_files) > 10:
        print(f"   ... และอีก {len(medium_files) - 10} ไฟล์")
    
    print(f"\n🔵 Low Priority Files ({len(low_files)} ไฟล์, {sum(len(f[1]) for f in low_files)} จุด):")
    for filepath, file_issues in low_files[:10]:
        print(f"   {filepath}: {len(file_issues)} จุด")
    if len(low_files) > 10:
        print(f"   ... และอีก {len(low_files) - 10} ไฟล์")
    
    print("\n✅ Phase 2.1 เสร็จสิ้น! (Analyze & Group)")
