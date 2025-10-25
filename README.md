<<<<<<< HEAD
# dLNk Attack Platform

**เครื่องมือโจมตีทางไซเบอร์อัตโนมัติที่ขับเคลื่อนด้วย AI**

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-Private-red)

---

## 📋 สารบัญ

- [ภาพรวม](#ภาพรวม)
- [คุณสมบัติหลัก](#คุณสมบัติหลัก)
- [สถาปัตยกรรมระบบ](#สถาปัตยกรรมระบบ)
- [การติดตั้ง](#การติดตั้ง)
- [การใช้งาน](#การใช้งาน)
- [API Documentation](#api-documentation)
- [CLI Commands](#cli-commands)
- [การพัฒนา](#การพัฒนา)
- [คำเตือน](#คำเตือน)

---

## ภาพรวม

**dLNk Attack Platform** เป็นแพลตฟอร์มโจมตีทางไซเบอร์อัตโนมัติที่ขับเคลื่อนด้วย AI ออกแบบมาสำหรับการทดสอบความปลอดภัยระดับมืออาชีพ ระบบใช้ **Local LLM (Ollama)** ในการวิเคราะห์และวางแผนการโจมตีแบบอัจฉริยะ พร้อมทั้งรองรับการโจมตีแบบ **One-Click** ที่ผู้ใช้เพียงแค่วาง URL เป้าหมาย ระบบจะดำเนินการโจมตีอัตโนมัติตั้งแต่ต้นจนจบ

### จุดเด่น

- **โจมตีอัตโนมัติ 100%** - วาง URL แล้วรอผลลัพธ์
- **AI-Powered Planning** - ใช้ Mixtral LLM ในการวางแผนการโจมตี
- **ครอบคลุมทุกช่องโหว่** - SQL Injection, XSS, Command Injection, SSRF, Auth Bypass, Zero-Day
- **Data Exfiltration** - ดึงข้อมูลสำคัญออกมาอัตโนมัติ
- **Real-time Monitoring** - ติดตามความคืบหน้าแบบเรียลไทม์
- **Key-based Authentication** - ไม่มีระบบสมัคร ใช้ Key เท่านั้น
- **รองรับทั้ง Web และ Terminal** - ใช้งานผ่าน API หรือ CLI

---

## คุณสมบัติหลัก

### 1. ระบบโจมตีอัตโนมัติ (Auto Attack System)

ระบบโจมตีแบบอัตโนมัติที่ครอบคลุมทุกขั้นตอน:

1. **Reconnaissance (10%)** - วิเคราะห์เป้าหมาย
   - IP Resolution
   - Port Scanning
   - Technology Detection
   - CMS/Framework Detection
   - SSL Analysis

2. **Vulnerability Scanning (25%)** - สแกนช่องโหว่
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Command Injection
   - Server-Side Request Forgery (SSRF)
   - Authentication Bypass
   - Zero-Day Discovery

3. **AI Vulnerability Analysis (40%)** - วิเคราะห์ช่องโหว่ด้วย AI
   - ประเมินความรุนแรง
   - จัดลำดับความสำคัญ
   - วิเคราะห์ความเป็นไปได้ในการโจมตี

4. **AI Attack Planning (50%)** - วางแผนการโจมตีด้วย AI
   - สร้างแผนการโจมตีที่เหมาะสม
   - เลือก Agent ที่เหมาะสม
   - กำหนด Payload และ Exploit

5. **Exploitation (60%)** - โจมตีตามแผน
   - รัน Exploit ตามลำดับ
   - บันทึกผลลัพธ์
   - Retry เมื่อล้มเหลว

6. **Post-Exploitation (75%)** - หลังการโจมตีสำเร็จ
   - Privilege Escalation
   - Lateral Movement
   - Persistence

7. **Data Exfiltration (85%)** - ดึงข้อมูลสำคัญ
   - Database Dump
   - File Download
   - Credential Extraction

8. **Cleanup (95%)** - ลบร่องรอย
   - ลบ Temporary Files
   - Reset Connections
   - Clear Logs

### 2. ระบบ Authentication แบบ Key-based

ระบบ Authentication ที่ไม่ต้องสมัครสมาชิก:

- **Admin Key** - สิทธิ์เต็มรูปแบบ, ไม่จำกัดการใช้งาน
- **User Key** - สิทธิ์จำกัด, มีจำนวนครั้งการใช้งาน
- **Usage Tracking** - ติดตามการใช้งานแต่ละ Key
- **Expiration Support** - กำหนดวันหมดอายุได้
- **Revoke Support** - ยกเลิก Key ได้ทันที

### 3. Admin Panel

ระบบจัดการสำหรับ Admin:

- **Key Management** - สร้าง, แก้ไข, ลบ, ยกเลิก API Key
- **User Management** - ดูรายชื่อผู้ใช้และประวัติการใช้งาน
- **System Settings** - ตั้งค่าระบบ รวมถึง **ลิงก์ LINE ติดต่อ Admin**
- **Statistics** - สถิติการโจมตี, ช่องโหว่, การใช้งาน
- **Activity Logs** - บันทึกการทำงานของ Admin

### 4. Terminal CLI

Command-line interface สำหรับใช้งานผ่าน Terminal:

```bash
# Launch attack
dlnk attack https://example.com

# Follow progress
dlnk attack https://example.com --follow

# Get status
dlnk status <attack_id>

# View history
dlnk history

# Admin commands
dlnk admin keys
```

### 5. Attack Agents

Agent ที่ใช้ในการโจมตี:

- **SQLMapAgent** - SQL Injection
- **XSSHunter** - Cross-Site Scripting (Reflected, DOM, Stored)
- **CommandInjectionExploiter** - Command Injection + Reverse Shell
- **SSRFAgentWeaponized** - Server-Side Request Forgery
- **AuthenticationBypassAgent** - Authentication Bypass
- **ZeroDayHunter** - Zero-Day Discovery (AI-powered)

---

## สถาปัตยกรรมระบบ

```
┌─────────────────────────────────────────────────────────────┐
│                        dLNk Platform                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                │
│  │  Web UI      │         │  Terminal    │                │
│  │  (React 19)  │         │  CLI         │                │
│  └──────┬───────┘         └──────┬───────┘                │
│         │                        │                         │
│         └────────────┬───────────┘                         │
│                      │                                     │
│              ┌───────▼────────┐                            │
│              │   FastAPI      │                            │
│              │   Backend      │                            │
│              └───────┬────────┘                            │
│                      │                                     │
│         ┌────────────┼────────────┐                        │
│         │            │            │                        │
│    ┌────▼───┐  ┌────▼────┐  ┌────▼────┐                  │
│    │  Auth  │  │ Attack  │  │  Admin  │                  │
│    │  API   │  │   API   │  │   API   │                  │
│    └────┬───┘  └────┬────┘  └────┬────┘                  │
│         │           │            │                         │
│         └───────────┼────────────┘                         │
│                     │                                      │
│            ┌────────▼─────────┐                            │
│            │  Attack          │                            │
│            │  Orchestrator    │                            │
│            └────────┬─────────┘                            │
│                     │                                      │
│        ┌────────────┼────────────┐                         │
│        │            │            │                         │
│   ┌────▼───┐  ┌────▼────┐  ┌────▼────┐                   │
│   │ Target │  │  Vuln   │  │   AI    │                   │
│   │Analyzer│  │ Scanner │  │ Planner │                   │
│   └────────┘  └────┬────┘  └────┬────┘                   │
│                    │            │                         │
│                    └──────┬─────┘                         │
│                           │                               │
│                  ┌────────▼─────────┐                     │
│                  │   Exploit        │                     │
│                  │   Executor       │                     │
│                  └────────┬─────────┘                     │
│                           │                               │
│                  ┌────────▼─────────┐                     │
│                  │  Attack Agents   │                     │
│                  │  (100+ Agents)   │                     │
│                  └──────────────────┘                     │
│                                                           │
├───────────────────────────────────────────────────────────┤
│                    External Services                      │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │PostgreSQL│  │  Ollama  │  │  Redis   │              │
│  │ Database │  │   LLM    │  │  Cache   │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## การติดตั้ง

### ความต้องการของระบบ

- **OS:** Ubuntu 22.04+ / WSL2
- **Python:** 3.11+
- **PostgreSQL:** 14+
- **Ollama:** Latest (สำหรับ Local LLM)
- **RAM:** 16GB+ (แนะนำ 32GB สำหรับ LLM)
- **Disk:** 50GB+

### ขั้นตอนการติดตั้ง

#### 1. Clone Repository

```bash
git clone https://github.com/vtvx4myqq9-stack/Manus.git
cd Manus/apex_predator_FINAL
```

#### 2. ติดตั้ง Dependencies

```bash
# สำหรับ Ubuntu/Debian
./wsl-fix.sh

# หรือติดตั้งแบบ Manual
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev \
    postgresql postgresql-contrib libpq-dev \
    build-essential libssl-dev libffi-dev

# สร้าง Virtual Environment
python3.11 -m venv venv
source venv/bin/activate

# ติดตั้ง Python Packages
pip install -r requirements-full.txt
```

#### 3. ติดตั้ง Ollama และ LLM

```bash
# ติดตั้ง Ollama
curl -fsSL https://ollama.com/install.sh | sh

# ดาวน์โหลด Mixtral model
ollama pull mixtral:latest

# ทดสอบ
ollama list
```

#### 4. ตั้งค่า PostgreSQL

```bash
# เริ่ม PostgreSQL
sudo service postgresql start

# สร้าง Database และ User
sudo -u postgres psql << EOF
CREATE DATABASE dlnk_attack_platform;
CREATE USER dlnk WITH PASSWORD 'dlnk';
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk;
ALTER DATABASE dlnk_attack_platform OWNER TO dlnk;
\q
EOF

# Import Schema
psql -U dlnk -d dlnk_attack_platform -h localhost < api/database/schema.sql
```

#### 5. ตั้งค่า Environment Variables

```bash
# สร้างไฟล์ .env
cp env.template .env

# แก้ไขไฟล์ .env
nano .env
```

**ไฟล์ .env:**

```bash
# Database
DATABASE_URL=postgresql://dlnk:dlnk@localhost:5432/dlnk_attack_platform

# Ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest

# API
API_HOST=0.0.0.0
API_PORT=8000

# Security
SIMULATION_MODE=False  # ⚠️ False = LIVE ATTACK MODE
```

#### 6. สร้าง Admin Key

```bash
# รัน Startup Script
python3 startup.py

# Script จะสร้าง Admin Key อัตโนมัติและแสดงผล
```

#### 7. เริ่มระบบ

```bash
# เริ่ม API Server
./run.sh

# หรือ
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

#### 8. ติดตั้ง CLI (Optional)

```bash
# ติดตั้ง CLI
./install_cli.sh

# ตั้งค่า API Key
export DLNK_API_KEY="your_admin_key_here"

# ทดสอบ
dlnk --help
=======
# dLNk Attack Platform v2.0

**AI-Powered Automated Attack Platform**

A sophisticated, fully automated offensive security platform powered by AI (Mixtral LLM) that can scan networks, discover vulnerabilities, plan and execute attacks, exploit systems, and exfiltrate data autonomously. Complete with API, user management, admin panel, and web interface.

---

## 🎯 Features

### Core Capabilities
- **100+ Attack Agents** - SQL Injection, XSS, Command Injection, SSRF, Authentication Bypass, Zero-Day Discovery, and more
- **AI-Powered Planning** - Mixtral LLM analyzes targets and creates custom attack strategies
- **Automated Workflows** - Pre-configured attack workflows for different scenarios
- **Data Exfiltration** - Automatically extract sensitive files and data from compromised systems
- **Real-time Monitoring** - WebSocket-based live updates and progress tracking
- **Multi-Channel Notifications** - Email, Telegram, Discord alerts for findings
- **Comprehensive Reporting** - HTML, JSON, Markdown reports with detailed findings

### Attack Categories
- **Web Application** - SQLi, XSS, SSRF, IDOR/BOLA, Authentication Bypass
- **API Security** - REST/GraphQL fuzzing, Authorization testing
- **Active Directory** - Kerberoasting, Pass-the-Hash, Golden Ticket, Zerologon
- **Cloud Security** - AWS, Azure, GCP exploitation
- **Network** - Port scanning, Service enumeration, Vulnerability scanning
- **Post-Exploitation** - Privilege escalation, Lateral movement, Persistence

---

## 🚀 Quick Start

### Prerequisites
- **Ubuntu/Debian/WSL** (recommended)
- **Python 3.8+**
- **PostgreSQL** (for database)
- **Ollama** with **mixtral:latest** model (for AI features)
- **Docker** (optional, for containerized deployment)

### Installation

#### For Linux/Ubuntu:

```bash
# Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# Run quick start script
./quickstart.sh
```

#### For WSL (Windows Subsystem for Linux):

```bash
# Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# Run WSL fix script first
./wsl-fix.sh

# Then run quick start
./quickstart.sh
```

**Note:** If you encounter issues on WSL, see [WSL_INSTALLATION_GUIDE.md](WSL_INSTALLATION_GUIDE.md) for detailed troubleshooting.

The script will:
1. Create Python virtual environment
2. Install dependencies
3. Check for Ollama and mixtral model
4. Create .env configuration
5. Initialize database
6. Generate admin API key

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-full.txt

# Copy and edit configuration
cp env.template .env
nano .env

# Initialize system
python3 startup.py
>>>>>>> 51ee436bc82130fea731e7fa1de298d5e47e2bc3
```

---

<<<<<<< HEAD
## การใช้งาน

### 1. ผ่าน API

#### Launch Attack

```bash
curl -X POST http://localhost:8000/api/attack/launch \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "attack_mode": "auto"
  }'
```

**Response:**

```json
{
  "attack_id": "abc123-def456-ghi789",
  "target_url": "https://example.com",
  "status": "queued",
  "message": "Attack launched successfully"
}
```

#### Get Status

```bash
curl -X GET http://localhost:8000/api/attack/abc123-def456-ghi789/status \
  -H "X-API-Key: YOUR_API_KEY"
```

**Response:**

```json
{
  "attack_id": "abc123-def456-ghi789",
  "target_url": "https://example.com",
  "status": "exploitation",
  "progress": 60,
  "started_at": "2025-10-23T10:00:00",
  "completed_at": null,
  "vulnerabilities_found": 5,
  "exploits_successful": 2,
  "data_exfiltrated_bytes": 0
}
```

#### Get Vulnerabilities

```bash
curl -X GET http://localhost:8000/api/attack/abc123-def456-ghi789/vulnerabilities \
  -H "X-API-Key: YOUR_API_KEY"
```

### 2. ผ่าน Terminal CLI

#### Launch Attack

```bash
# Basic attack
dlnk attack https://example.com

# Stealth mode
dlnk attack https://example.com --mode stealth

# Follow progress
dlnk attack https://example.com --follow
```

#### Get Status

```bash
dlnk status abc123-def456-ghi789
```

#### View History

```bash
dlnk history
dlnk history --limit 20
```

#### Stop Attack

```bash
dlnk stop abc123-def456-ghi789
```

#### Admin Commands

```bash
# List all API keys
dlnk admin keys
```

### 3. Attack Modes

- **auto** (แนะนำ) - สมดุลระหว่างความเร็วและความปลอดภัย
- **stealth** - ความลับสูงสุด, ช้ากว่า, หลบเลี่ยงการตรวจจับ
- **aggressive** - เร็วที่สุด, มีประสิทธิภาพสูงสุด, อาจถูกตรวจจับ

---

## API Documentation

### Authentication

ทุก API endpoint ต้องการ API Key ใน header:

```
X-API-Key: dlnk_<64_hex_characters>
```

### Endpoints

#### Attack API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/attack/launch` | Launch attack |
| GET | `/api/attack/{id}/status` | Get attack status |
| GET | `/api/attack/{id}/vulnerabilities` | Get vulnerabilities |
| POST | `/api/attack/{id}/stop` | Stop attack |
| GET | `/api/attack/history` | Get attack history |
| DELETE | `/api/attack/{id}` | Delete attack |

#### Admin API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/admin/keys/create` | Create API key |
| GET | `/api/admin/keys` | List all keys |
| GET | `/api/admin/keys/{id}` | Get key details |
| PATCH | `/api/admin/keys/{id}` | Update key |
| POST | `/api/admin/keys/{id}/revoke` | Revoke key |
| DELETE | `/api/admin/keys/{id}` | Delete key |
| GET | `/api/admin/stats` | Get statistics |
| GET | `/api/admin/settings` | Get settings |
| PUT | `/api/admin/settings/{key}` | Update setting |

#### System Settings

| Setting Key | Description |
|-------------|-------------|
| `line_contact_url` | **ลิงก์ LINE ติดต่อ Admin** |
| `default_usage_limit` | จำนวนครั้งการใช้งานเริ่มต้น |
| `rate_limit_per_minute` | Rate limit ต่อนาที |
| `attack_timeout_seconds` | Timeout การโจมตี |
| `data_retention_days` | จำนวนวันเก็บข้อมูล |

---

## CLI Commands

### Basic Commands

```bash
# Show help
dlnk --help

# Show version
dlnk --version

# Launch attack
dlnk attack <url>

# Get status
dlnk status <attack_id>

# View history
dlnk history

# Stop attack
dlnk stop <attack_id>
```

### Admin Commands

```bash
# List API keys
dlnk admin keys
```

### Environment Variables

```bash
# API Key (required)
export DLNK_API_KEY="your_api_key_here"

# API URL (optional, default: http://localhost:8000)
export DLNK_API_URL="http://your-server:8000"
=======
## 🔧 Configuration

Edit `.env` file with your settings:

```bash
# Core Settings
SIMULATION_MODE=False  # False = Live Attack Mode
DATABASE_URL=postgresql://user:pass@localhost:5432/dlnk_dlnk

# Ollama LLM
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
LLM_PROVIDER=ollama

# Workspace
WORKSPACE_DIR=workspace
LOOT_DIR=workspace/loot

# Notifications (optional)
NOTIFICATION_CHANNELS=email,telegram,discord
SMTP_HOST=smtp.gmail.com
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
TELEGRAM_BOT_TOKEN=your-bot-token
DISCORD_WEBHOOK_URL=your-webhook-url
```

---

## 🎮 Usage

### Start API Server

```bash
# Using run script
./run.sh

# Or manually
source venv/bin/activate
python3 api/main.py
```

API will be available at:
- **API:** localhost:8000
- **Docs:** localhost:8000/docs
- **Admin Key:** See `ADMIN_KEY.txt`

### API Examples

#### 1. Start Full Auto Attack

```bash
curl -X POST localhost:8000/api/attack/start \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "localhost:8000",
    "attack_type": "full_auto"
  }'
```

#### 2. Check Attack Status

```bash
curl localhost:8000/api/attack/{attack_id}/status \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 3. Get Attack Results

```bash
curl localhost:8000/api/attack/{attack_id}/results \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 4. List Exfiltrated Files

```bash
curl localhost:8000/api/files/attack/{attack_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 5. Generate Report

```bash
curl -X POST localhost:8000/api/attack/{attack_id}/report \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

### Attack Types

- **full_auto** - Complete automated attack (scan → exploit → post-exploit)
- **scan** - Vulnerability scanning only
- **exploit** - Exploitation phase only
- **post_exploit** - Post-exploitation activities
- **zero_day_hunt** - AI-powered zero-day discovery
- **sql_injection** - SQL injection testing
- **xss** - XSS vulnerability testing
- **command_injection** - Command injection testing

---

## 🐳 Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Services:
- **API Server:** localhost:8000
- **PostgreSQL:** localhost:5432
- **Ollama:** http://localhost:11434

---

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Auth    │  │  Attack  │  │  Admin   │  │  Files   │  │
│  │  Routes  │  │  Routes  │  │  Routes  │  │  Routes  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Service Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Attack     │  │    Agent     │  │     Tool     │     │
│  │   Manager    │  │   Executor   │  │   Verifier   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Notification │  │   Database   │  │   WebSocket  │     │
│  │   Service    │  │   Service    │  │   Manager    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Core Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  AI Attack   │  │   Enhanced   │  │     LLM      │     │
│  │  Strategist  │  │  AI Planner  │  │   Provider   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Orchestrator │  │   Workflow   │  │  Vulnerability│     │
│  │              │  │   Executor   │  │   Analyzer   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Agent Layer (100+ Agents)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ SQLMap   │  │   XSS    │  │ Command  │  │ Zero-Day │  │
│  │  Agent   │  │  Hunter  │  │ Injection│  │  Hunter  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   Auth   │  │   SSRF   │  │   BOLA   │  │   Data   │  │
│  │  Bypass  │  │  Agent   │  │  Agent   │  │ Exfiltrator│ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│                      ... and 90+ more                       │
└─────────────────────────────────────────────────────────────┘
>>>>>>> 51ee436bc82130fea731e7fa1de298d5e47e2bc3
```

---

<<<<<<< HEAD
## การพัฒนา

### โครงสร้างโปรเจกต์

```
apex_predator_FINAL/
├── api/                    # Backend API
│   ├── database/          # Database layer
│   ├── middleware/        # Authentication middleware
│   ├── routes/            # API routes
│   └── services/          # Business logic
├── core/                   # Core systems
│   ├── attack_orchestrator.py
│   ├── target_analyzer.py
│   ├── ai_attack_planner.py
│   ├── vulnerability_scanner.py
│   └── exploit_executor.py
├── agents/                 # Attack agents
│   ├── sqlmap_agent.py
│   ├── command_injection_exploiter.py
│   └── ...
├── advanced_agents/        # Advanced agents
│   ├── xss_hunter.py
│   ├── auth_bypass.py
│   └── zero_day_hunter.py
├── data_exfiltration/     # Data exfiltration
│   └── exfiltrator.py
├── cli/                    # Terminal CLI
│   └── dlnk.py
├── config/                 # Configuration
│   └── settings.py
└── workflows/              # Attack workflows
```

### การเพิ่ม Agent ใหม่

1. สร้างไฟล์ใน `agents/` หรือ `advanced_agents/`
2. Implement methods: `scan()`, `exploit()`
3. เพิ่มใน `vulnerability_scanner.py`
4. เพิ่มใน `exploit_executor.py`

### การทดสอบ

```bash
# Run tests
pytest tests/

# Run specific test
pytest tests/test_attack_orchestrator.py

# Run with coverage
pytest --cov=. tests/
=======
## ⚠️ Legal Disclaimer

**THIS IS AN OFFENSIVE SECURITY ATTACK PLATFORM**

- ✅ **Authorized Use:** Bug bounty programs, authorized security assessments with written permission, your own systems and networks
- ❌ **Unauthorized Use:** Attacking systems without explicit authorization is **ILLEGAL** and punishable by law

**You are responsible for:**
- Obtaining explicit written authorization before any attack operations
- Complying with all applicable laws and regulations
- Any damage, legal consequences, or liabilities caused by use or misuse of this platform

**The developers assume NO LIABILITY for misuse of this software.**

---

## 📚 Documentation

- **API Documentation:** localhost:8000/docs (when running)
- **DEPLOYMENT_GUIDE.md:** Complete deployment and configuration guide
- **NEWPLAN.MD:** Development roadmap and features

---

## 🛠️ Development

### Project Structure

```
dlnk_dlnk_FINAL/
├── agents/              # 100+ Attack agents
├── advanced_agents/     # Advanced agents (Zero-Day, XSS, Auth Bypass)
├── api/                 # FastAPI backend
│   ├── routes/         # API endpoints
│   ├── services/       # Business logic
│   └── middleware/     # Rate limiting, etc.
├── config/             # Configuration and workflows
├── core/               # Core systems (AI, Orchestrator, etc.)
├── data_exfiltration/  # Data exfiltration system
├── startup.py          # System initialization
├── quickstart.sh       # Quick start script
└── run.sh              # Run script
```

### Adding New Agents

1. Create agent file in `agents/` or `advanced_agents/`
2. Inherit from base agent class
3. Implement `run()` or `execute()` method
4. Agent will be auto-discovered on startup

Example:

```python
class MyCustomAgent:
    """My custom attack agent"""
    
    def __init__(self, target_url: str, **options):
        self.target_url = target_url
        self.options = options
    
    def run(self):
        # Your attack logic here
        vulnerabilities = []
        
        # ... perform attack ...
        
        return {
            "success": True,
            "vulnerabilities": vulnerabilities
        }
>>>>>>> 51ee436bc82130fea731e7fa1de298d5e47e2bc3
```

---

<<<<<<< HEAD
## คำเตือน

### ⚠️ คำเตือนสำคัญ

**ระบบนี้อยู่ใน LIVE ATTACK MODE (SIMULATION_MODE=False)**

**ห้ามใช้กับเป้าหมายที่ไม่ได้รับอนุญาต!**

การใช้งานที่ถูกต้อง:
- ✅ Penetration Testing ที่ได้รับอนุญาต
- ✅ Bug Bounty Programs
- ✅ ระบบที่คุณเป็นเจ้าของ
- ✅ Lab Environment

การใช้งานที่ผิดกฎหมาย:
- ❌ โจมตีระบบที่ไม่ได้รับอนุญาต
- ❌ ทดสอบเว็บไซต์ที่ไม่ใช่ของคุณ
- ❌ ใช้เพื่อวัตถุประสงค์ที่ผิดกฎหมาย

**การใช้งานโดยไม่ได้รับอนุญาตเป็นการกระทำผิดกฎหมาย**

### กฎหมายที่เกี่ยวข้อง

- พ.ร.บ. คอมพิวเตอร์ พ.ศ. 2550
- พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act

---

## ติดต่อ

- **LINE:** [ติดต่อ Admin ผ่าน LINE](https://line.me/ti/p/YOUR_LINE_ID)
- **GitHub:** https://github.com/vtvx4myqq9-stack/Manus
- **Email:** admin@dlnk.local

---

## License

**Private - All Rights Reserved**

โปรเจกต์นี้เป็นของส่วนตัว ห้ามทำซ้ำ แจกจ่าย หรือใช้งานโดยไม่ได้รับอนุญาต

---

## Credits

**Developed by:** dLNk Team  
**Powered by:** Ollama (Mixtral), FastAPI, React 19  
**Version:** 2.0.0  
**Last Updated:** October 23, 2025

---

**🎯 dLNk - Advanced Penetration Testing Platform**
=======
## 🤝 Contributing

This is a private research project. Contact the repository owner for collaboration opportunities.

---

## 📝 License

This project is an offensive security attack platform. Use only with explicit authorization. Educational use must be in controlled, isolated environments.

---

## 🔗 Links

- **GitHub:** https://github.com/donlasahachat1-sys/manus
- **Ollama:** https://ollama.ai
- **Mixtral Model:** https://ollama.ai/library/mixtral

---

## 📧 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Built with ❤️ for the security research community**

**Version:** 2.0  
**Last Updated:** October 2025
>>>>>>> 51ee436bc82130fea731e7fa1de298d5e47e2bc3

