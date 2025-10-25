#!/usr/bin/env python3
"""
Phase 4: แก้ไข Environment Variables
เพิ่ม default value ให้ os.getenv()
"""

import re
from pathlib import Path
from typing import Tuple

def fix_env_vars(filepath: Path) -> Tuple[bool, int]:
    """แก้ไข os.getenv() ให้มี default value"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        fixes = 0
        
        for i, line in enumerate(lines):
            # ตรวจหา os.getenv("KEY", "") หรือ os.getenv('KEY', "") ที่ไม่มี default
            # Pattern: os.getenv("KEY", "") แต่ไม่มี comma
            match = re.search(r'os\.getenv\(["\']([^"\']+)["\']\)(?!\s*,)', line)
            
            if match:
                var_name = match.group(1)
                
                # กำหนด default value ตามประเภทของตัวแปร
                if 'URL' in var_name or 'PATH' in var_name or 'DIR' in var_name:
                    default = '""'
                elif 'PORT' in var_name:
                    default = '"8000"'
                elif 'KEY' in var_name or 'TOKEN' in var_name or 'SECRET' in var_name:
                    default = '""'
                elif 'TIMEOUT' in var_name:
                    default = '"120"'
                else:
                    default = '""'
                
                # แทนที่
                new_line = line.replace(
                    f'os.getenv("{var_name}", "")',
                    f'os.getenv("{var_name}", {default})'
                ).replace(
                    f"os.getenv('{var_name}', "")",
                    f"os.getenv('{var_name}', {default})"
                )
                
                if new_line != line:
                    lines[i] = new_line
                    modified = True
                    fixes += 1
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, fixes
        
        return False, 0
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False, 0

if __name__ == "__main__":
    print("🔧 เริ่มแก้ไข Environment Variables...\n")
    
    total_fixes = 0
    files_fixed = 0
    
    for py_file in Path('.').rglob("*.py"):
        if '__pycache__' in str(py_file) or 'venv' in str(py_file):
            continue
        
        modified, fixes = fix_env_vars(py_file)
        if modified:
            print(f"✅ {py_file}: เพิ่ม default {fixes} จุด")
            total_fixes += fixes
            files_fixed += 1
    
    print(f"\n✅ เสร็จสิ้น!")
    print(f"   แก้ไข: {total_fixes} จุดใน {files_fixed} ไฟล์")
