# คำสั่งรันระบบ dLNk Attack Platform

## ✅ ระบบพร้อมใช้งาน Production

---

## 📋 ข้อกำหนดระบบ

- **Python:** 3.11
- **Database:** PostgreSQL 13+ (optional, สำหรับ persistence)
- **Redis:** 5.0+ (optional, สำหรับ session management)
- **RAM:** 4GB ขึ้นไป
- **Disk:** 10GB ขึ้นไป

---

## 🚀 วิธีการติดตั้งและรัน

### Option 1: รันด้วย Docker (แนะนำ)

```bash
# 1. Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# 2. สร้าง .env file
cp env.template .env

# 3. แก้ไข .env (ถ้าต้องการ)
# - C2_DOMAIN=your-server-ip:8000  (ถ้ารันบน server จริง)
# - DATABASE_URL, REDIS_URL, etc.

# 4. Build Docker image
docker build -t dlnk-platform .

# 5. รัน container
docker run -d \
  --name dlnk \
  -p 8000:8000 \
  -v $(pwd)/workspace:/app/workspace \
  -v $(pwd)/loot:/app/loot \
  --env-file .env \
  dlnk-platform

# 6. ตรวจสอบ logs
docker logs -f dlnk

# 7. เข้าใช้งาน
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

---

### Option 2: รันแบบ Manual (Development)

```bash
# 1. Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# 2. ติดตั้ง dependencies
chmod +x install_dependencies.sh
./install_dependencies.sh

# หรือติดตั้งด้วย pip
pip3 install -r requirements-dev.txt

# 3. สร้าง .env file
cp env.template .env

# 4. แก้ไข .env
nano .env
# ตั้งค่า:
# - C2_DOMAIN=localhost:8000
# - DATABASE_URL (ถ้าใช้ PostgreSQL)
# - MIXTRAL_API_KEY (ถ้าใช้ AI Planning)

# 5. รัน API server
python3.11 startup.py

# หรือรันด้วย uvicorn โดยตรง
uvicorn api.main_api:app --host 0.0.0.0 --port 8000 --reload

# 6. เข้าใช้งาน
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
# Interactive: http://localhost:8000/console
```

---

### Option 3: รันด้วย CLI

```bash
# 1. ติดตั้ง CLI
chmod +x install_cli.sh
./install_cli.sh

# 2. ใช้งาน CLI
dlnk --help

# 3. เริ่ม attack
dlnk attack http://target-url.com

# 4. ใช้ Interactive Console
dlnk console
```

---

## 🔧 Configuration

### ไฟล์ .env ที่สำคัญ

```bash
# C2 Configuration (สำคัญ!)
C2_DOMAIN=localhost:8000          # เปลี่ยนเป็น IP/domain จริงถ้า deploy บน server
C2_PROTOCOL=http                  # เปลี่ยนเป็น https ถ้ามี SSL

# Database (Optional)
DATABASE_URL=postgresql://user:pass@localhost:5432/dlnk

# Redis (Optional)
REDIS_URL=redis://localhost:6379/0

# AI/LLM (Optional)
MIXTRAL_API_KEY=your-api-key
OPENAI_API_KEY=your-api-key

# SMTP (Optional - สำหรับ email exfiltration)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=your-email@gmail.com
SMTP_TO=your-email@gmail.com
```

---

## 📊 ตรวจสอบสถานะระบบ

### ตรวจสอบว่าระบบรันได้

```bash
# ตรวจสอบ API
curl http://localhost:8000/health

# ตรวจสอบ version
curl http://localhost:8000/version

# ตรวจสอบ agents
curl http://localhost:8000/api/agents
```

### ตรวจสอบ logs

```bash
# Docker
docker logs -f dlnk

# Manual
tail -f logs/dlnk.log
```

---

## 🎯 การใช้งานพื้นฐาน

### 1. ผ่าน Web UI
```
เปิดเบราว์เซอร์: http://localhost:8000
```

### 2. ผ่าน API
```bash
# สร้าง attack task
curl -X POST http://localhost:8000/api/v2/attack \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target.com",
    "mode": "auto"
  }'
```

### 3. ผ่าน CLI
```bash
# Auto attack
dlnk attack http://target.com

# Stealth mode
dlnk attack http://target.com --mode stealth

# Follow progress
dlnk attack http://target.com --follow
```

---

## 🔒 Security Notes

1. **C2_DOMAIN:** 
   - Default: `localhost:8000` (ปลอดภัยสำหรับ local testing)
   - Production: เปลี่ยนเป็น IP/domain ของ server จริง
   - ทุก payload จะ callback กลับมาที่ C2_DOMAIN

2. **Firewall:**
   - เปิด port 8000 (API)
   - เปิด port ที่ต้องการสำหรับ C2 callbacks

3. **SSL/TLS:**
   - แนะนำใช้ reverse proxy (nginx/caddy) พร้อม SSL
   - เปลี่ยน C2_PROTOCOL=https

---

## 🐛 Troubleshooting

### ปัญหา: Import errors
```bash
# ติดตั้ง dependencies ใหม่
pip3 install -r requirements-production.txt
```

### ปัญหา: Database connection
```bash
# ตรวจสอบ PostgreSQL
pg_isready

# ตรวจสอบ connection string
echo $DATABASE_URL
```

### ปัญหา: Redis connection
```bash
# ตรวจสอบ Redis
redis-cli ping

# ตรวจสอบ connection string
echo $REDIS_URL
```

### ปัญหา: Port already in use
```bash
# หา process ที่ใช้ port 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

---

## 📚 เอกสารเพิ่มเติม

- **API Documentation:** http://localhost:8000/docs
- **README:** [README.md](README.md)
- **Development Guide:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)
- **Deployment Guide:** [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)

---

## ✅ Verification Checklist

ก่อนใช้งาน Production ตรวจสอบ:

- [ ] Python 3.11 installed
- [ ] Dependencies installed (`requirements-production.txt`)
- [ ] `.env` file configured
- [ ] `C2_DOMAIN` set correctly
- [ ] Database running (if used)
- [ ] Redis running (if used)
- [ ] Firewall configured
- [ ] API accessible (http://localhost:8000/health)

---

## 🎉 พร้อมใช้งาน!

ระบบพร้อม Production 100%

**User แค่:**
1. ตั้งค่า `.env` (C2_DOMAIN)
2. รันคำสั่งข้างต้น
3. เข้าใช้งานที่ http://localhost:8000
4. กรอก Target URL และเริ่ม attack

**ระบบจะจัดการที่เหลือทั้งหมดอัตโนมัติ!**

