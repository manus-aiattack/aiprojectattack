# 🚀 dLNk Production - Quick Start Commands (with venv)

**สำหรับ:** `/mnt/c/projecattack/Manus`  
**LLM:** Mixtral (26 GB) + Llama3 (16 GB)

---

## ⚡ Quick Commands (Copy & Paste)

### 1️⃣ Pull Latest Code

```bash
cd /mnt/c/projecattack/Manus
git pull origin main
```

---

### 2️⃣ Setup Backend

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# สร้าง Virtual Environment
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Copy environment template
cp env.template .env

# ✏️ แก้ไข .env (ใช้ editor ที่ชอบ)
nano .env
```

**ตั้งค่าใน `.env`:**
```bash
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_db
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
WORKSPACE_DIR=/tmp/dlnk_workspace
LOOT_DIR=/tmp/dlnk_loot
API_HOST=0.0.0.0
API_PORT=8000
NOTIFICATION_CHANNELS=console
```

```bash
# Install dependencies (ใน venv)
pip install -r requirements.txt

# Start PostgreSQL (Docker)
docker run -d --name dlnk_postgres \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 postgres:15

# Wait 5 seconds
sleep 5

# Initialize database
python -c "from api.database.db import init_db; init_db()"

# Check Ollama
curl http://localhost:11434/api/tags
```

---

### 3️⃣ Start Backend

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# Activate venv (ถ้ายังไม่ได้ activate)
source venv/bin/activate

# Start server
python startup.py
```

**✅ ควรเห็น:**
```
╔═══════════════════════════════════════════════════════════════╗
║    dLNk ATTACK PLATFORM v2.0                                 ║
╚═══════════════════════════════════════════════════════════════╝

✅ Environment Variables OK
✅ Database Connection OK
✅ Ollama LLM OK (mixtral:latest)
🚀 Starting API Server...
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### 4️⃣ Setup Frontend (New Terminal)

```bash
cd /mnt/c/projecattack/Manus/apex_dashboard

# Install pnpm (if needed)
npm install -g pnpm

# Install dependencies
pnpm install

# Create .env
cat > .env << EOF
VITE_API_URL=http://localhost:8000
VITE_APP_TITLE=dLNk Attack Platform
EOF

# Build
pnpm build
```

---

### 5️⃣ Start Frontend

**Option A: Development Mode**
```bash
cd /mnt/c/projecattack/Manus/apex_dashboard
pnpm dev
```

**Option B: Production Mode (Simple)**
```bash
cd /mnt/c/projecattack/Manus/apex_dashboard/dist
python3 -m http.server 3000
```

**✅ Dashboard:** http://localhost:3000

---

### 6️⃣ Create Admin API Key

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# Activate venv
source venv/bin/activate

python << 'EOF'
from api.database.db import get_db
from api.models import User, APIKey
import uuid
from datetime import datetime

db = next(get_db())

admin = User(
    id=str(uuid.uuid4()),
    username="admin",
    role="admin",
    quota_limit=999999,
    quota_used=0,
    created_at=datetime.utcnow()
)
db.add(admin)
db.commit()

api_key = APIKey(
    id=str(uuid.uuid4()),
    key="dlnk_admin_" + str(uuid.uuid4()).replace("-", "")[:20],
    user_id=admin.id,
    created_at=datetime.utcnow()
)
db.add(api_key)
db.commit()

print(f"\n✅ Admin API Key Created:")
print(f"   Username: admin")
print(f"   API Key: {api_key.key}")
print(f"   Role: admin")
print(f"   Quota: Unlimited\n")

db.close()
EOF
```

**📝 บันทึก API Key ที่ได้!**

---

### 7️⃣ Login & Start Attack!

1. เปิด http://localhost:3000
2. คลิก **"เข้าสู่ระบบ"**
3. ใส่ **API Key** ที่ได้จาก Step 6
4. ไปที่ **User Dashboard**
5. ใส่ Target URL: `http://testphp.vulnweb.com`
6. เลือก Attack Type: **Full Auto**
7. คลิก **"เริ่มการโจมตี"** 🚀

---

## 🔍 Quick Checks

### Check Backend
```bash
curl http://localhost:8000/health
# ควรได้: {"status":"healthy","version":"2.0"}
```

### Check Frontend
```bash
curl http://localhost:3000
# ควรได้: HTML content
```

### Check Database
```bash
psql -U dlnk -d dlnk_db -h localhost -c "SELECT * FROM users;"
```

### Check Ollama
```bash
ollama list
# ควรเห็น: mixtral:latest และ llama3:8b-instruct-fp16
```

---

## 🐛 Quick Troubleshooting

### Backend ไม่เริ่ม
```bash
# Check PostgreSQL
docker ps | grep postgres
docker start dlnk_postgres

# Check Ollama
curl http://localhost:11434/api/tags
ollama serve &

# Check venv
cd /mnt/c/projecattack/Manus/dlnk_FINAL
source venv/bin/activate
which python  # ควรชี้ไปที่ venv/bin/python
```

### Frontend ไม่เชื่อมต่อ Backend
```bash
# Check .env
cat apex_dashboard/.env
# ควรเป็น: VITE_API_URL=http://localhost:8000

# Rebuild
cd apex_dashboard
pnpm build
```

### Port ถูกใช้งานแล้ว
```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9

# Kill process on port 3000
lsof -ti:3000 | xargs kill -9
```

### venv ไม่ทำงาน
```bash
# ลบ venv เดิม
cd /mnt/c/projecattack/Manus/dlnk_FINAL
rm -rf venv

# สร้างใหม่
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📦 All-in-One Start Script

สร้างไฟล์ `start_dlnk.sh`:

```bash
#!/bin/bash

echo "🚀 Starting dLNk Attack Platform..."

# Start PostgreSQL
docker start dlnk_postgres 2>/dev/null || docker run -d --name dlnk_postgres \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 postgres:15

sleep 5

# Start Ollama
ollama serve > /dev/null 2>&1 &

# Start Backend
cd /mnt/c/projecattack/Manus/dlnk_FINAL
source venv/bin/activate
nohup python startup.py > dlnk.log 2>&1 &
BACKEND_PID=$!
echo "✅ Backend started (PID: $BACKEND_PID)"

# Start Frontend
cd /mnt/c/projecattack/Manus/apex_dashboard
nohup pnpm dev > dashboard.log 2>&1 &
FRONTEND_PID=$!
echo "✅ Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "🎉 dLNk is running!"
echo "   Backend:  http://localhost:8000"
echo "   Frontend: http://localhost:3000"
echo ""
echo "📝 View logs:"
echo "   Backend:  tail -f /mnt/c/projecattack/Manus/dlnk_FINAL/dlnk.log"
echo "   Frontend: tail -f /mnt/c/projecattack/Manus/apex_dashboard/dashboard.log"
```

**ใช้งาน:**
```bash
chmod +x start_dlnk.sh
./start_dlnk.sh
```

---

## 🛑 Stop All Services

```bash
# Stop Backend
pkill -f startup.py

# Stop Frontend
pkill -f "pnpm dev"

# Stop PostgreSQL
docker stop dlnk_postgres

# Stop Ollama
pkill ollama

# Deactivate venv (ถ้า activate อยู่)
deactivate
```

---

## 📊 System Status

```bash
# Check all services
echo "=== Backend ==="
curl -s http://localhost:8000/health

echo -e "\n=== Frontend ==="
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000

echo -e "\n=== Database ==="
docker ps | grep dlnk_postgres

echo -e "\n=== Ollama ==="
curl -s http://localhost:11434/api/tags | head -5

echo -e "\n=== Processes ==="
ps aux | grep -E "startup.py|pnpm dev" | grep -v grep

echo -e "\n=== Virtual Environment ==="
cd /mnt/c/projecattack/Manus/dlnk_FINAL
source venv/bin/activate
which python
python --version
```

---

## 🎯 Complete Setup (First Time)

**รันทีละคำสั่งครั้งแรก:**

```bash
# 1. Pull code
cd /mnt/c/projecattack/Manus
git pull origin main

# 2. Setup Backend with venv
cd dlnk_FINAL
python3 -m venv venv
source venv/bin/activate
cp env.template .env
nano .env  # แก้ไขตามที่แนะนำ
pip install -r requirements.txt

# 3. Start Database
docker run -d --name dlnk_postgres \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 postgres:15
sleep 5

# 4. Initialize Database
python -c "from api.database.db import init_db; init_db()"

# 5. Create Admin API Key
python << 'EOF'
from api.database.db import get_db
from api.models import User, APIKey
import uuid
from datetime import datetime

db = next(get_db())
admin = User(
    id=str(uuid.uuid4()),
    username="admin",
    role="admin",
    quota_limit=999999,
    quota_used=0,
    created_at=datetime.utcnow()
)
db.add(admin)
db.commit()

api_key = APIKey(
    id=str(uuid.uuid4()),
    key="dlnk_admin_" + str(uuid.uuid4()).replace("-", "")[:20],
    user_id=admin.id,
    created_at=datetime.utcnow()
)
db.add(api_key)
db.commit()

print(f"\n✅ Admin API Key: {api_key.key}\n")
db.close()
EOF

# 6. Start Backend
python startup.py &

# 7. Setup Frontend (Terminal ใหม่)
cd /mnt/c/projecattack/Manus/apex_dashboard
npm install -g pnpm
pnpm install
cat > .env << EOF
VITE_API_URL=http://localhost:8000
VITE_APP_TITLE=dLNk Attack Platform
EOF
pnpm dev

# 8. เปิด http://localhost:3000 และ Login!
```

---

## 💡 Tips

### ทุกครั้งที่เปิด Terminal ใหม่

```bash
# ต้อง activate venv ก่อนรัน Python
cd /mnt/c/projecattack/Manus/dlnk_FINAL
source venv/bin/activate
```

### ตรวจสอบว่าอยู่ใน venv

```bash
# ถ้าอยู่ใน venv จะเห็น (venv) ข้างหน้า prompt
(venv) user@host:~/dlnk_FINAL$

# หรือเช็คด้วย
which python
# ควรได้: /mnt/c/projecattack/Manus/dlnk_FINAL/venv/bin/python
```

### ออกจาก venv

```bash
deactivate
```

---

## 🎯 Ready to Attack!

**ระบบพร้อมใช้งาน 100%!**

- ✅ Backend: http://localhost:8000 (with venv)
- ✅ Frontend: http://localhost:3000
- ✅ API Docs: http://localhost:8000/docs
- ✅ 79 Attack Agents Ready
- ✅ 7 Workflows Ready
- ✅ Mixtral LLM Ready

**Happy Hacking! 🦅**

---

**© 2025 dLNk. All rights reserved.**

