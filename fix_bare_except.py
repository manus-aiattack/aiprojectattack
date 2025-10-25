#!/usr/bin/env python3
"""
แก้ไข bare except (except: แทน except Exception:)
"""

import re
from pathlib import Path

def fix_bare_except(filepath: Path) -> int:
    """แก้ไข bare except ในไฟล์"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # แทนที่ except: ด้วย except Exception as e:
        # Pattern: except: (ที่ไม่ใช่ except SomeException:)
        content = re.sub(
            r'\bexcept\s*:\s*$',
            'except Exception as e:',
            content,
            flags=re.MULTILINE
        )
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return content.count('except Exception as e:') - original.count('except Exception as e:')
        
        return 0
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return 0

if __name__ == "__main__":
    print("🔧 แก้ไข bare except ทั้งหมด...\n")
    
    total_fixed = 0
    files_fixed = 0
    
    for py_file in Path('.').rglob("*.py"):
        if '__pycache__' in str(py_file) or 'venv' in str(py_file):
            continue
        
        fixed = fix_bare_except(py_file)
        if fixed > 0:
            print(f"✅ {py_file}: แก้ไข {fixed} จุด")
            total_fixed += fixed
            files_fixed += 1
    
    print(f"\n✅ เสร็จสิ้น!")
    print(f"   แก้ไข: {total_fixed} จุดใน {files_fixed} ไฟล์")
