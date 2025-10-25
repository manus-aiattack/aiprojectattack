#!/usr/bin/env python3
"""
แก้ไขปัญหา Critical ทั้งหมด
"""

import os
import re
from pathlib import Path

def fix_hardcoded_paths():
    """แก้ไข hardcoded paths"""
    fixes = []
    
    files_to_fix = [
        ("ai_testing_system.py", [
            (r"'/home/ubuntu/ai_test_results\.json'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_results.json')"),
            (r"'/home/ubuntu/ai_test_summary\.json'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_summary.json')"),
            (r"'/home/ubuntu/ai_test_report\.md'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_report.md')"),
        ]),
        ("agents/deserialization_exploiter.py", [
            (r'"/home/ubuntu/ysoserial\.jar"', 'os.getenv("YSOSERIAL_PATH", os.path.join(os.path.expanduser("~"), "ysoserial.jar"))'),
        ]),
        ("agents/evasion/anti_debug.py", [
            (r"'/home/malware'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'malware')"),
        ]),
        ("data_exfiltration/exfiltrator.py", [
            (r'"/home/"', 'os.path.expanduser("~") + "/"'),
        ]),
        # dlnk_FINAL directory
        ("dlnk_FINAL/ai_testing_system.py", [
            (r"'/home/ubuntu/ai_test_results\.json'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_results.json')"),
            (r"'/home/ubuntu/ai_test_summary\.json'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_summary.json')"),
            (r"'/home/ubuntu/ai_test_report\.md'", "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'ai_test_report.md')"),
        ]),
        ("dlnk_FINAL/agents/deserialization_exploiter.py", [
            (r'"workspace/loot/deserialization"', "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'loot', 'deserialization')"),
        ]),
        ("dlnk_FINAL/agents/lfi_agent.py", [
            (r'"workspace/loot/lfi"', "os.path.join(os.getenv('WORKSPACE_DIR', 'workspace'), 'loot', 'lfi')"),
            (r"'/var/www/html/' \+ filepath\.lstrip\('/'", "os.path.join(os.getenv('TARGET_WEB_ROOT', '/var/www/html'), filepath.lstrip('/'))"),
        ]),
    ]
    
    for filename, replacements in files_to_fix:
        filepath = Path(filename)
        if not filepath.exists():
            continue
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            for pattern, replacement in replacements:
                content = re.sub(pattern, replacement, content)
            
            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                fixes.append(f"✅ Fixed: {filename}")
        except Exception as e:
            fixes.append(f"❌ Error fixing {filename}: {e}")
    
    return fixes

def fix_payload_manager():
    """แก้ไข payload_manager.py"""
    filepath = Path("core/payload_manager.py")
    if not filepath.exists():
        return []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # เพิ่ม exist_ok=True
        content = re.sub(
            r'os\.makedirs\(([^)]+)\)(?!\s*,\s*exist_ok)',
            r'os.makedirs(\1, exist_ok=True)',
            content
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return ["✅ Fixed: core/payload_manager.py"]
    except Exception as e:
        return [f"❌ Error fixing payload_manager: {e}"]

if __name__ == "__main__":
    print("🔧 เริ่มแก้ไขปัญหา Critical...")
    print()
    
    fixes = []
    fixes.extend(fix_hardcoded_paths())
    fixes.extend(fix_payload_manager())
    
    print("\n".join(fixes))
    print()
    print(f"✅ แก้ไขเสร็จสิ้น: {len([f for f in fixes if '✅' in f])} ไฟล์")
