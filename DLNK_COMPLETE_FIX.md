# dLNk Complete Fix Guide

## ปัญหาที่พบ

### 1. requirements.txt ไม่ครบ
- ❌ ไฟล์ `requirements.txt` มีแค่ 5 packages
- ✅ ต้องใช้ `requirements-full.txt` แทน (87 packages)

### 2. Dependencies ที่ขาดหายไป
```
aiofiles, beautifulsoup4, pyyaml, asyncpg, fastapi, uvicorn, redis, 
loguru, psutil, dnspython, angr, boto3, pymetasploit3, python-dotenv
```

### 3. startup.py มี bugs
- ❌ ตรวจสอบ beautifulsoup4 และ pyyaml ผิดพลาด (ใช้ชื่อ module ผิด)
- ❌ Database connection ใช้ synchronous แทน async
- ❌ Import error: `cannot import name 'get_database'`

### 4. PostgreSQL authentication
- ❌ Container ต้องรอให้พร้อมก่อน (20+ วินาที)
- ✅ ต้องสร้าง tables ด้วยมือ

---

## ✅ วิธีแก้ไขแบบสมบูรณ์

### Step 1: ติดตั้ง Dependencies ครบถ้วน

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# Activate venv
source venv/bin/activate

# ติดตั้งจาก requirements-full.txt
pip install -r requirements-full.txt

# ติดตั้ง packages เพิ่มเติมที่ขาด
pip install \
  angr \
  boto3 \
  pymetasploit3 \
  python-dotenv \
  aiofiles \
  bs4
```

### Step 2: Setup PostgreSQL

```bash
# ลบ container เดิม (ถ้ามี)
docker stop dlnk_postgres 2>/dev/null
docker rm dlnk_postgres 2>/dev/null

# สร้างใหม่
docker run -d --name dlnk_postgres \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 \
  postgres:15

# รอให้พร้อม (สำคัญมาก!)
echo "Waiting for PostgreSQL..."
sleep 25

# ตรวจสอบว่าพร้อม
docker exec dlnk_postgres pg_isready -U dlnk
```

### Step 3: สร้าง Database Schema

```bash
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db << 'EOF'
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    role VARCHAR NOT NULL,
    quota_limit INTEGER DEFAULT 100,
    quota_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR PRIMARY KEY,
    key VARCHAR UNIQUE NOT NULL,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attacks table
CREATE TABLE IF NOT EXISTS attacks (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    target_url VARCHAR NOT NULL,
    attack_type VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- LINE URLs table (for dLNk specific)
CREATE TABLE IF NOT EXISTS line_urls (
    id VARCHAR PRIMARY KEY,
    url VARCHAR UNIQUE NOT NULL,
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Show tables
\dt
EOF
```

### Step 4: สร้าง Admin API Key

```bash
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db << 'EOF'
-- Insert admin user
INSERT INTO users (id, username, role, quota_limit, quota_used, created_at)
VALUES (
    'admin-' || substr(md5(random()::text), 1, 8),
    'admin',
    'admin',
    999999,
    0,
    CURRENT_TIMESTAMP
)
ON CONFLICT (username) DO NOTHING;

-- Insert admin API key
INSERT INTO api_keys (id, key, user_id, created_at)
SELECT 
    'key-' || substr(md5(random()::text), 1, 8),
    'dlnk_admin_' || substr(md5(random()::text), 1, 20),
    id,
    CURRENT_TIMESTAMP
FROM users WHERE username = 'admin'
ON CONFLICT (key) DO NOTHING;

-- Show admin API key
SELECT 
    u.username,
    u.role,
    u.quota_limit,
    k.key as api_key
FROM users u
JOIN api_keys k ON k.user_id = u.id
WHERE u.username = 'admin';
EOF
```

**📝 บันทึก API Key ที่แสดงออกมา!**

### Step 5: Setup Environment Variables

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# Export ทั้งหมด
export DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_db
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=mixtral:latest
export WORKSPACE_DIR=/tmp/dlnk_workspace
export LOOT_DIR=/tmp/dlnk_loot
export API_HOST=0.0.0.0
export API_PORT=8000
export NOTIFICATION_CHANNELS=console

# สร้าง .env file
cat > .env << 'EOF'
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_db
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
WORKSPACE_DIR=/tmp/dlnk_workspace
LOOT_DIR=/tmp/dlnk_loot
API_HOST=0.0.0.0
API_PORT=8000
NOTIFICATION_CHANNELS=console
EOF
```

### Step 6: Start API Server (ข้าม startup.py)

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL
source venv/bin/activate

# รัน API Server โดยตรง
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

**ถ้ามี error ให้ดูที่ Step 7**

---

## Step 7: แก้ไข startup.py (ถ้าต้องการใช้)

### ปัญหาใน startup.py

1. **Line ~50-60:** ตรวจสอบ beautifulsoup4 ผิด
```python
# ❌ ผิด
import beautifulsoup4  # ไม่มี module ชื่อนี้

# ✅ ถูก
import bs4
```

2. **Line ~100-120:** Database connection แบบ sync
```python
# ❌ ผิด
import psycopg2
conn = psycopg2.connect(...)

# ✅ ถูก
import asyncpg
conn = await asyncpg.connect(...)
```

3. **Line ~200:** Import error
```python
# ❌ ผิด
from api.services.database import get_database

# ✅ ถูก
from api.database.db import get_db
```

### แก้ไข startup.py

```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL

# Backup
cp startup.py startup.py.backup

# แก้ไขด้วย sed
sed -i 's/import beautifulsoup4/import bs4/g' startup.py
sed -i 's/beautifulsoup4\.__version__/bs4.__version__/g' startup.py
```

**หรือแก้ไขด้วยมือ:**

```bash
nano startup.py
```

ค้นหาและแก้ไข:
- `import beautifulsoup4` → `import bs4`
- `beautifulsoup4.__version__` → `bs4.__version__`
- `from api.services.database import get_database` → `from api.database.db import get_db`

---

## Step 8: Start Frontend Dashboard

**Terminal ใหม่:**

```bash
cd /mnt/c/projecattack/Manus/apex_dashboard

# Install dependencies (ถ้ายังไม่ได้ติดตั้ง)
pnpm install

# Create .env
cat > .env << 'EOF'
VITE_API_URL=http://localhost:8000
VITE_APP_TITLE=dLNk Attack Platform
EOF

# Start dev server
pnpm dev
```

---

## Step 9: Verify Everything

### Check Backend
```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","version":"2.0"}
```

### Check Frontend
```bash
curl http://localhost:3000
# Expected: HTML content
```

### Check Database
```bash
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db -c "SELECT COUNT(*) FROM users;"
# Expected: 1 (admin user)
```

### Check Ollama
```bash
curl http://localhost:11434/api/tags
# Expected: JSON with models list
```

---

## Step 10: Login to Dashboard

1. เปิด http://localhost:3000
2. คลิก **"เข้าสู่ระบบ"**
3. ใส่ **Admin API Key** จาก Step 4
4. เข้าสู่ **Dashboard**
5. เริ่มโจมตี! 🚀

---

## 🐛 Troubleshooting

### Error: "No module named 'aiofiles'"
```bash
pip install aiofiles
```

### Error: "No module named 'bs4'"
```bash
pip install beautifulsoup4
```

### Error: "password authentication failed"
```bash
# รอให้ PostgreSQL พร้อม
sleep 30
docker exec dlnk_postgres pg_isready -U dlnk
```

### Error: "cannot import name 'get_database'"
```bash
# ใช้ uvicorn โดยตรง แทน startup.py
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Port 8000 ถูกใช้งานแล้ว
```bash
lsof -ti:8000 | xargs kill -9
```

### venv ไม่ทำงาน
```bash
cd /mnt/c/projecattack/Manus/dlnk_FINAL
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-full.txt
```

---

## 📋 Complete Command List (Copy & Paste)

```bash
# ===== 1. Setup venv & Install Dependencies =====
cd /mnt/c/projecattack/Manus/dlnk_FINAL
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-full.txt
pip install angr boto3 pymetasploit3 python-dotenv aiofiles bs4

# ===== 2. Setup PostgreSQL =====
docker stop dlnk_postgres 2>/dev/null
docker rm dlnk_postgres 2>/dev/null
docker run -d --name dlnk_postgres \
  -e POSTGRES_USER=dlnk \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_db \
  -p 5432:5432 \
  postgres:15
sleep 25
docker exec dlnk_postgres pg_isready -U dlnk

# ===== 3. Create Database Schema =====
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    role VARCHAR NOT NULL,
    quota_limit INTEGER DEFAULT 100,
    quota_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR PRIMARY KEY,
    key VARCHAR UNIQUE NOT NULL,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attacks (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    target_url VARCHAR NOT NULL,
    attack_type VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS line_urls (
    id VARCHAR PRIMARY KEY,
    url VARCHAR UNIQUE NOT NULL,
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
\dt
EOF

# ===== 4. Create Admin API Key =====
docker exec -i dlnk_postgres psql -U dlnk -d dlnk_db << 'EOF'
INSERT INTO users (id, username, role, quota_limit, quota_used, created_at)
VALUES (
    'admin-' || substr(md5(random()::text), 1, 8),
    'admin',
    'admin',
    999999,
    0,
    CURRENT_TIMESTAMP
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO api_keys (id, key, user_id, created_at)
SELECT 
    'key-' || substr(md5(random()::text), 1, 8),
    'dlnk_admin_' || substr(md5(random()::text), 1, 20),
    id,
    CURRENT_TIMESTAMP
FROM users WHERE username = 'admin'
ON CONFLICT (key) DO NOTHING;

SELECT 
    u.username,
    u.role,
    u.quota_limit,
    k.key as api_key
FROM users u
JOIN api_keys k ON k.user_id = u.id
WHERE u.username = 'admin';
EOF

# ===== 5. Setup Environment =====
export DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_db
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=mixtral:latest
export WORKSPACE_DIR=/tmp/dlnk_workspace
export LOOT_DIR=/tmp/dlnk_loot
export API_HOST=0.0.0.0
export API_PORT=8000
export NOTIFICATION_CHANNELS=console

cat > .env << 'EOF'
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_db
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
WORKSPACE_DIR=/tmp/dlnk_workspace
LOOT_DIR=/tmp/dlnk_loot
API_HOST=0.0.0.0
API_PORT=8000
NOTIFICATION_CHANNELS=console
EOF

# ===== 6. Start Backend =====
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# ===== 7. Start Frontend (Terminal ใหม่) =====
cd /mnt/c/projecattack/Manus/apex_dashboard
pnpm install
cat > .env << 'EOF'
VITE_API_URL=http://localhost:8000
VITE_APP_TITLE=dLNk Attack Platform
EOF
pnpm dev

# ===== 8. Open Dashboard =====
# http://localhost:3000
```

---

## ✅ สรุป

**ปัญหาหลัก:**
1. ❌ `requirements.txt` ไม่ครบ → ใช้ `requirements-full.txt`
2. ❌ `startup.py` มี bugs → ใช้ `uvicorn` โดยตรง
3. ❌ PostgreSQL ต้องรอให้พร้อม → `sleep 25`
4. ❌ Database schema ไม่มี → สร้างด้วย SQL

**วิธีแก้:**
- ✅ ติดตั้ง dependencies ครบถ้วนจาก `requirements-full.txt`
- ✅ Setup PostgreSQL และสร้าง schema ด้วยมือ
- ✅ ข้าม `startup.py` ใช้ `uvicorn` โดยตรง
- ✅ Export environment variables ก่อนรัน

**ผลลัพธ์:**
- ✅ Backend API: http://localhost:8000
- ✅ Frontend Dashboard: http://localhost:3000
- ✅ API Docs: http://localhost:8000/docs
- ✅ 116 Attack Agents Ready
- ✅ Mixtral + Llama3 LLM Ready

**Happy Hacking! 🦅**

