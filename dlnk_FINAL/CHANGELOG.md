# Changelog - dLNk dLNk Framework

## [v3.0-dLNk] - 2025-10-22

### 🎯 Major Changes - Transformation to Offensive Security Framework

**นี่ไม่ใช่การทดสอบ แต่คือระบบโจมตีจริง**

### ✨ New Features

#### 1. License & Security System
- **License Manager** (`core/license_manager.py`)
  - Time-based licenses (1 hour, 1-30 days, 1-12 months)
  - Usage-based licenses (limited uses)
  - Terminal locking (one license per terminal)
  - Encrypted license keys with PBKDF2HMAC
- **License CLI** (`cli/license_cli.py`)
  - `dlnk-dlnk license generate` - สร้าง license key
  - `dlnk-dlnk license activate` - เปิดใช้งาน license
  - `dlnk-dlnk license info` - ดูข้อมูล license
  - `dlnk-dlnk license revoke` - ยกเลิก license
  - `dlnk-dlnk license unlock` - ปลด terminal lock

#### 2. Attack-Focused CLI
- **Attack CLI** (`cli/attack_cli.py`)
  - `dlnk-dlnk attack scan` - สแกนหาช่องโหว่
  - `dlnk-dlnk attack exploit` - ใช้ประโยชน์จากช่องโหว่
  - `dlnk-dlnk attack post-exploit` - ดำเนินการหลังโจมตี
- **Logical 3-Phase Attack Flow**
  1. **SCAN**: Reconnaissance → Vulnerability Scanning → Analysis
  2. **EXPLOIT**: Vulnerability Exploitation → Shell Acquisition
  3. **POST-EXPLOIT**: Privilege Escalation → Persistence → Data Exfiltration

#### 3. Hardcore UI/UX
- **UI Module** (`cli/ui.py`)
  - ASCII art logo with dark red theme
  - **dLNk branding** with rainbow colors (🌈)
  - Consistent color scheme across all outputs
  - Legal notice on every startup

#### 4. New Agent: IDOR
- **IDOR Agent** (`agents/idor_agent.py`)
  - Detects Insecure Direct Object Reference vulnerabilities
  - Tests sequential ID enumeration
  - Tests UUID/GUID patterns
  - Tests hash-based IDs
  - Automatic exploitation with data extraction

#### 5. Full Auto Attack Workflow
- **attack_full_auto_workflow.yaml** (`config/attack_full_auto_workflow.yaml`)
  - 11-phase automated attack chain
  - From reconnaissance to covering tracks
  - 100% automation - no human intervention required
  - Includes:
    - Reconnaissance
    - Vulnerability Scanning
    - Exploitation
    - Shell Upgrade
    - Privilege Escalation
    - Persistence (Backdoor)
    - Lateral Movement
    - Data Exfiltration
    - Covering Tracks
    - Reporting

### 📚 Documentation Updates

#### 1. dLNkV1.MD - AI Handoff Document
- Complete system architecture documentation
- Current status of all systems
- Agent roster with status
- Mission briefing for next AI developer
- Priority tasks for future development

#### 2. THAI_USER_GUIDE.md - Thai Language Guide
- **Complete rewrite** to emphasize offensive nature
- Removed all references to "testing" or "simulation"
- Added license management guide
- Added attack operations guide
- Added agent catalog

### 🔧 Performance Improvements

#### Redis Optimizations
- Connection pooling for better concurrency
- Pipeline operations for batch updates
- Reduced network overhead

#### Context Manager
- Batch updates using HMSET
- Optimized data serialization
- Reduced Redis calls

### 🧪 Testing

- Added comprehensive test suite (`tests/test_orchestrator.py`)
- All core systems tested
- Mock-based testing for isolated unit tests

### 🐛 Bug Fixes

- Fixed agent discovery path issues
- Fixed data model validation errors
- Fixed async/await handling in orchestrator
- Fixed Redis client initialization
- Fixed logging system integration

### 📦 Dependencies

- Added `cryptography` for license encryption
- Added `pytest-asyncio` for async testing
- Updated all dependencies to latest versions

### 🚀 Deployment

- Docker Compose ready
- Environment variable configuration
- Automated setup scripts
- Production-ready configuration

---

## [v2.0] - Previous Version

### Features
- Basic agent system
- Workflow execution
- Web dashboard
- REST API

---

## Future Roadmap

### v4.0 (Planned)
- Interactive console (msfconsole-style)
- Full web GUI with Vue.js
- Browser-based shell access
- Advanced evasion techniques
- Machine learning for exploit selection

### v5.0 (Planned)
- Distributed attack coordination
- Multi-target campaigns
- Advanced persistence mechanisms
- Custom exploit development tools

---

**Powered by dLNk Framework**

