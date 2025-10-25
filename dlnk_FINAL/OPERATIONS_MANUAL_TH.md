# คู่มือการปฏิบัติงาน - dLNk Attack Platform

## 1. บทนำ
เอกสารนี้ให้ข้อมูลที่จำเป็นสำหรับการติดตั้ง, การปรับแต่ง, การตรวจสอบ, และการแก้ไขปัญหา dLNk Attack Platform.

## 2. การติดตั้งและการปรับใช้ (Deployment)

### 2.1. ข้อกำหนดเบื้องต้น
*   ระบบปฏิบัติการ Linux (Ubuntu/Debian แนะนำ)
*   Docker และ Docker Compose (เวอร์ชันล่าสุด)
*   ทรัพยากรระบบที่แนะนำ (CPU, RAM, GPU สำหรับ AI Planner)

### 2.2. การติดตั้งแบบ Single-Node (สำหรับ Development/Testing)
*   **การโคลน Repository:** `git clone [repository_url]`
*   **การตั้งค่าไฟล์ `.env`:**
    *   คัดลอก `env.template` เป็น `.env`
    *   แก้ไขค่าตัวแปรที่สำคัญ เช่น `SECRET_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD` (ต้องเปลี่ยนเป็นรหัสผ่านที่รัดกุม)
*   **การรันด้วย Docker Compose:** `docker-compose up --build -d`
*   **การตรวจสอบสถานะ:** `docker-compose ps`
*   **การเข้าถึง Dashboard:** `http://localhost:8000` (หรือพอร์ตที่กำหนด)

### 2.3. การติดตั้งแบบ Distributed (สำหรับ Production)
*   **การตั้งค่าไฟล์ `.env.production`:**
    *   คัดลอก `env.template` เป็น `.env.production`
    *   แก้ไขค่าตัวแปรที่สำคัญทั้งหมด โดยเฉพาะรหัสผ่านและคีย์ลับต่างๆ
*   **การรันด้วย Docker Compose (Distributed):** `docker-compose -f docker-compose.distributed.yml up --build -d`
*   **การตรวจสอบสถานะ:** `docker-compose -f docker-compose.distributed.yml ps`
*   **การเข้าถึง API Gateway:** `http://localhost:80` (หรือพอร์ตที่กำหนด)
*   **การเข้าถึง Grafana Dashboard:** `http://localhost:3000` (รหัสผ่านเริ่มต้น: `admin_change_me` - **ต้องเปลี่ยนทันที**)

### 2.4. การปรับใช้บน Kubernetes (K8s)
*   **ข้อกำหนดเบื้องต้น:** คลัสเตอร์ Kubernetes ที่พร้อมใช้งาน, `kubectl`, `helm`.
*   **การตั้งค่า Secrets:** การสร้าง Kubernetes Secrets สำหรับรหัสผ่านและคีย์ลับต่างๆ (อ้างอิงจาก `k8s/*.yaml`).
*   **การปรับใช้:** `kubectl apply -f k8s/` หรือใช้ Helm charts (ถ้ามี).

## 3. การปรับแต่ง (Configuration)

### 3.1. ตัวแปรสภาพแวดล้อม (Environment Variables)
*   รายการตัวแปรที่สำคัญและคำอธิบาย (อ้างอิงจาก `config/settings.py` และ `.env.template`).
*   **`SECRET_KEY`:** คีย์ลับสำหรับ JWT และการเข้ารหัส (ต้องเป็นค่าที่สุ่มและยาว).
*   **`DB_PASSWORD`:** รหัสผ่านสำหรับ PostgreSQL.
*   **`REDIS_PASSWORD`:** รหัสผ่านสำหรับ Redis.
*   **`OLLAMA_HOST`:** ที่อยู่ของ Ollama LLM Server.
*   **`LLM_MODEL_PATH`:** พาธสำหรับโมเดล LLM (สำหรับ AI Planner).
*   **`API_DEBUG`:** โหมด Debug (ควรเป็น `False` ใน Production).

### 3.2. การตั้งค่าระบบ (System Settings)
*   การปรับแต่งผ่าน Admin Panel (`/api/admin/settings`).
*   `rate_limit_per_minute`, `attack_timeout_seconds`, `data_retention_days`.

### 3.3. การตั้งค่า CORS
*   การปรับแต่ง `allow_origins` ใน `api/main.py` สำหรับ Production.

## 4. การตรวจสอบและบันทึก (Monitoring & Logging)

### 4.1. การตรวจสอบสถานะบริการ
*   **Docker Compose:** `docker-compose ps`, `docker-compose logs -f [service_name]`.
*   **Kubernetes:** `kubectl get pods`, `kubectl logs [pod_name]`.
*   **API Health Check:** `GET /health` endpoint.
*   **API Status:** `GET /status` endpoint.

### 4.2. การเข้าถึง Log
*   **ไฟล์ Log:** Log จะถูกบันทึกในโฟลเดอร์ `logs/` (ใน Volume ที่ Mount ไว้).
*   **WebSocket Log Stream:** `ws/logs` endpoint สำหรับ Log แบบ Real-time.
*   **Grafana Dashboard:** การตั้งค่า Grafana สำหรับการแสดงผล Metrics และ Log (ถ้ามีการติดตั้ง).

### 4.3. การแจ้งเตือน (Notifications)
*   การตั้งค่าช่องทางการแจ้งเตือน (Telegram, Email, Discord) ผ่าน Environment Variables.

## 5. การแก้ไขปัญหา (Troubleshooting)

### 5.1. ปัญหาการเชื่อมต่อฐานข้อมูล
*   ตรวจสอบ `DB_PASSWORD` ใน `.env` หรือ Kubernetes Secret.
*   ตรวจสอบสถานะคอนเทนเนอร์ `db` หรือ `postgres`.
*   ตรวจสอบ Firewall.

### 5.2. ปัญหา Redis
*   ตรวจสอบ `REDIS_PASSWORD`.
*   ตรวจสอบสถานะคอนเทนเนอร์ `redis`.

### 5.3. ปัญหา LLM (Ollama/AI Planner)
*   ตรวจสอบสถานะคอนเทนเนอร์ `ollama` หรือ `ai-planner`.
*   ตรวจสอบ `OLLAMA_HOST` หรือ `LLM_MODEL_PATH`.
*   ตรวจสอบการใช้งาน GPU (สำหรับ `ai-planner`).

### 5.4. API ไม่ตอบสนอง
*   ตรวจสอบสถานะคอนเทนเนอร์ `api` หรือ `orchestrator`.
*   ตรวจสอบ Log เพื่อหาข้อผิดพลาด.

### 5.5. การกู้คืนข้อมูล (Data Recovery)
*   การสำรองข้อมูล PostgreSQL และ Redis Volumes.
*   ขั้นตอนการกู้คืนข้อมูลจาก Backup.

## 6. การบำรุงรักษา
*   **การอัปเดต:** ขั้นตอนการอัปเดต Framework และ Dependencies.
*   **การทำความสะอาด:** การล้างข้อมูลเก่า (Log, ผลลัพธ์การโจมตี) ตาม `data_retention_days`.
*   **การตรวจสอบความปลอดภัย:** การรัน Static Analysis Tools (Bandit, Mypy) และการตรวจสอบช่องโหว่เป็นประจำ.