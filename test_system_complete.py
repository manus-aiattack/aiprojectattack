#!/usr/bin/env python3
"""
ทดสอบระบบ dLNk Attack Platform ครบถ้วน
"""
import os
import sys

sys.path.insert(0, '/home/ubuntu/manus')

def test_imports():
    """ทดสอบ import ระบบหลัก"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 1: Import ระบบหลัก")
    print("="*80)
    
    tests = [
        ("core.orchestrator", "Orchestrator"),
        ("api.main", "app"),
        ("agents.nmap_agent", None),
        ("agents.sqlmap_agent", None),
        ("core.ai_integration", "AIIntegration"),
        ("core.tool_manager", "ToolManager"),
        ("api.services.database", "Database"),
    ]
    
    passed = 0
    failed = 0
    
    for module_name, class_name in tests:
        try:
            if class_name:
                exec(f"from {module_name} import {class_name}")
                print(f"✅ {module_name}.{class_name}")
            else:
                exec(f"import {module_name}")
                print(f"✅ {module_name}")
            passed += 1
        except Exception as e:
            print(f"❌ {module_name} - Error: {e}")
            failed += 1
    
    print(f"\n📊 ผลลัพธ์: ✅ {passed} | ❌ {failed}")
    return passed, failed

def test_config():
    """ทดสอบ configuration"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 2: Configuration")
    print("="*80)
    
    # ตรวจสอบ .env
    env_file = "/home/ubuntu/manus/.env"
    if os.path.exists(env_file):
        print(f"✅ .env file exists")
        with open(env_file, 'r') as f:
            lines = f.readlines()
        print(f"   Lines: {len(lines)}")
    else:
        print(f"❌ .env file not found")
    
    # ตรวจสอบ workspace
    workspace = os.getenv("WORKSPACE_DIR", "workspace")
    if os.path.exists(workspace):
        print(f"✅ Workspace exists: {workspace}")
        subdirs = os.listdir(workspace)
        print(f"   Subdirs: {', '.join(subdirs[:5])}")
    else:
        print(f"❌ Workspace not found: {workspace}")

def test_database():
    """ทดสอบ database connection"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 3: Database")
    print("="*80)
    
    try:
        from api.services.database import Database
        print("✅ Database module imported")
        
        # ตรวจสอบ DATABASE_URL
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            print(f"✅ DATABASE_URL configured")
            # ซ่อน password
            safe_url = db_url.split('@')[1] if '@' in db_url else db_url
            print(f"   Host: {safe_url}")
        else:
            print(f"⚠️  DATABASE_URL not set")
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")

def test_api():
    """ทดสอบ API"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 4: API Endpoints")
    print("="*80)
    
    try:
        from api.main import app
        print("✅ API app imported")
        
        # ดู routes
        routes = [route.path for route in app.routes]
        print(f"   Total routes: {len(routes)}")
        print(f"   Sample routes:")
        for route in routes[:5]:
            print(f"      {route}")
            
    except Exception as e:
        print(f"❌ API test failed: {e}")

def test_agents():
    """ทดสอบ agents"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 5: Attack Agents")
    print("="*80)
    
    agent_files = [
        "agents/nmap_agent.py",
        "agents/sqlmap_agent.py",
        "agents/nuclei_agent.py",
        "agents/metasploit_agent.py",
    ]
    
    passed = 0
    for agent_file in agent_files:
        if os.path.exists(agent_file):
            print(f"✅ {agent_file}")
            passed += 1
        else:
            print(f"❌ {agent_file} not found")
    
    print(f"\n📊 Agents found: {passed}/{len(agent_files)}")

def test_llm():
    """ทดสอบ LLM integration"""
    print("\n" + "="*80)
    print("🔍 ทดสอบ 6: LLM Integration")
    print("="*80)
    
    # ตรวจสอบ API keys
    openai_key = os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    
    if openai_key:
        print(f"✅ OPENAI_API_KEY configured")
    else:
        print(f"⚠️  OPENAI_API_KEY not set")
    
    if anthropic_key:
        print(f"✅ ANTHROPIC_API_KEY configured")
    else:
        print(f"⚠️  ANTHROPIC_API_KEY not set")
    
    print(f"✅ OLLAMA_HOST: {ollama_host}")
    
    # ตรวจสอบ llm_wrapper
    if os.path.exists("core/llm_wrapper.py"):
        print(f"✅ LLM wrapper exists")
    else:
        print(f"❌ LLM wrapper not found")

def main():
    print("\n" + "🚀" * 40)
    print("dLNk Attack Platform - System Test")
    print("🚀" * 40)
    
    # รัน tests
    test_imports()
    test_config()
    test_database()
    test_api()
    test_agents()
    test_llm()
    
    print("\n" + "="*80)
    print("✅ ทดสอบเสร็จสิ้น!")
    print("="*80)

if __name__ == "__main__":
    main()

