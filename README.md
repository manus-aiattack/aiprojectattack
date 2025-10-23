# dLNk Attack Platform v2.0

**AI-Powered Automated Penetration Testing System**

A sophisticated, fully automated penetration testing framework powered by AI (Mixtral LLM) that can discover vulnerabilities, plan attacks, generate exploits, and exfiltrate data autonomously.

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
```

---

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
- **API:** http://localhost:8000
- **Docs:** http://localhost:8000/docs
- **Admin Key:** See `ADMIN_KEY.txt`

### API Examples

#### 1. Start Full Auto Attack

```bash
curl -X POST http://localhost:8000/api/attack/start \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "attack_type": "full_auto"
  }'
```

#### 2. Check Attack Status

```bash
curl http://localhost:8000/api/attack/{attack_id}/status \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 3. Get Attack Results

```bash
curl http://localhost:8000/api/attack/{attack_id}/results \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 4. List Exfiltrated Files

```bash
curl http://localhost:8000/api/files/attack/{attack_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

#### 5. Generate Report

```bash
curl -X POST http://localhost:8000/api/attack/{attack_id}/report \
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
- **API Server:** http://localhost:8000
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
```

---

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

- ✅ **Authorized Use:** Bug bounty programs, penetration testing with written permission, your own systems
- ❌ **Unauthorized Use:** Attacking systems without permission is **ILLEGAL**

**You are responsible for:**
- Obtaining proper authorization before testing
- Complying with all applicable laws
- Any damage caused by misuse of this tool

**The developers assume NO LIABILITY for misuse of this software.**

---

## 📚 Documentation

- **API Documentation:** http://localhost:8000/docs (when running)
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
```

---

## 🤝 Contributing

This is a private research project. Contact the repository owner for collaboration opportunities.

---

## 📝 License

This project is for educational and authorized security testing purposes only.

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

