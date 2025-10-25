#!/usr/bin/env python3
"""
Phase 3: Apply LLM Wrapper
แก้ไข LLM calls ให้ใช้ wrapper หรือเพิ่ม timeout
"""

import re
from pathlib import Path
from typing import List, Tuple

def fix_llm_calls(filepath: Path) -> Tuple[bool, int]:
    """แก้ไข LLM calls ในไฟล์"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        fixes = 0
        
        # ตรวจสอบว่ามี timeout parameter หรือไม่
        # Pattern: client.chat.completions.create(...)
        pattern = r'(self\.client|client)\.chat\.completions\.create\('
        
        matches = list(re.finditer(pattern, content))
        
        for match in reversed(matches):  # ทำจากท้ายไปหน้าเพื่อไม่ให้ position เปลี่ยน
            start = match.end()
            
            # หาจุดสิ้นสุดของ function call (หา matching parenthesis)
            paren_count = 1
            end = start
            while end < len(content) and paren_count > 0:
                if content[end] == '(':
                    paren_count += 1
                elif content[end] == ')':
                    paren_count -= 1
                end += 1
            
            # ดึง parameters
            params_section = content[start:end-1]
            
            # ตรวจสอบว่ามี timeout หรือไม่
            if 'timeout' not in params_section:
                # เพิ่ม timeout parameter
                # หาจุดที่จะแทรก (ก่อน closing paren)
                insert_pos = end - 1
                
                # ตรวจสอบว่ามี comma ท้ายสุดหรือไม่
                params_stripped = params_section.rstrip()
                if params_stripped and not params_stripped.endswith(','):
                    content = content[:insert_pos] + ',\n                timeout=120' + content[insert_pos:]
                else:
                    content = content[:insert_pos] + '\n                timeout=120' + content[insert_pos:]
                
                fixes += 1
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, fixes
        
        return False, 0
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False, 0

if __name__ == "__main__":
    print("🔧 เริ่มแก้ไข LLM Calls...\n")
    
    # ไฟล์ที่ต้องแก้ไข
    files_to_fix = [
        "ai_testing_system.py",
        "apex_ai_system.py",
        "apex_ai_system_local.py",
        "core/ai_integration.py",
        "dlnk_FINAL/ai_testing_system.py",
        "dlnk_FINAL/apex_ai_system.py",
        "dlnk_FINAL/core/ai_integration.py",
        "tests/test_all.py",
    ]
    
    total_fixes = 0
    files_fixed = 0
    
    for filepath_str in files_to_fix:
        filepath = Path(filepath_str)
        if not filepath.exists():
            print(f"⚠️  ไม่พบไฟล์: {filepath}")
            continue
        
        modified, fixes = fix_llm_calls(filepath)
        if modified:
            print(f"✅ {filepath}: เพิ่ม timeout {fixes} จุด")
            total_fixes += fixes
            files_fixed += 1
        else:
            print(f"⚠️  {filepath}: ไม่มีการเปลี่ยนแปลง")
    
    print(f"\n✅ เสร็จสิ้น!")
    print(f"   แก้ไข: {total_fixes} จุดใน {files_fixed} ไฟล์")
