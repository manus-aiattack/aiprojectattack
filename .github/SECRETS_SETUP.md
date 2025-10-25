# GitHub Secrets Configuration Guide

## Required Secrets for CI/CD Pipeline

### Docker Hub Secrets (Required for Docker Build)

เพื่อให้ workflow สามารถ build และ push Docker images ได้ ต้องตั้งค่า secrets ดังนี้:

1. **DOCKER_USERNAME**
   - ชื่อผู้ใช้ Docker Hub ของคุณ
   - ตั้งค่าที่: Settings → Secrets and variables → Actions → New repository secret
   - ตัวอย่าง: `yourusername`

2. **DOCKER_PASSWORD**
   - Password หรือ Access Token ของ Docker Hub
   - แนะนำให้ใช้ Access Token แทน password เพื่อความปลอดภัย
   - สร้าง Access Token ที่: https://hub.docker.com/settings/security
   - ตั้งค่าที่: Settings → Secrets and variables → Actions → New repository secret

### Production Deployment Secrets (Optional - ถ้าต้องการ enable deploy job)

ถ้าต้องการเปิดใช้งาน automatic deployment ให้ตั้งค่า secrets เหล่านี้:

3. **PROD_HOST**
   - IP address หรือ domain ของ production server
   - ตัวอย่าง: `192.168.1.100` หรือ `prod.example.com`

4. **PROD_USERNAME**
   - Username สำหรับ SSH เข้า production server
   - ตัวอย่าง: `ubuntu` หรือ `deploy`

5. **PROD_SSH_KEY**
   - Private SSH key สำหรับเข้าถึง production server
   - ต้องเป็น private key ที่มี public key ติดตั้งอยู่ใน server แล้ว
   - รูปแบบ: เนื้อหาทั้งหมดของไฟล์ `~/.ssh/id_rsa` หรือ key อื่นๆ

6. **PROD_URL**
   - URL ของ production application สำหรับ health check
   - ตัวอย่าง: `https://prod.example.com`

7. **SLACK_WEBHOOK** (Optional)
   - Slack webhook URL สำหรับรับ notification
   - สร้างได้ที่: https://api.slack.com/messaging/webhooks
   - ตัวอย่าง: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX`

## วิธีตั้งค่า Secrets

1. ไปที่ repository ของคุณบน GitHub
2. คลิก **Settings** (ต้องมีสิทธิ์ admin)
3. ไปที่ **Secrets and variables** → **Actions**
4. คลิก **New repository secret**
5. กรอก **Name** และ **Value**
6. คลิก **Add secret**

## การเปิดใช้งาน Deploy Job

หลังจากตั้งค่า secrets ครบแล้ว ให้แก้ไขไฟล์ `.github/workflows/ci-cd.yml`:

```yaml
deploy:
  name: Deploy to Production
  runs-on: ubuntu-latest
  needs: [docker-build]
  if: true  # เปลี่ยนจาก false เป็น true
```

## การตรวจสอบ Secrets

ใช้คำสั่ง GitHub CLI (ต้องมีสิทธิ์เพียงพอ):

```bash
gh secret list
```

หรือตรวจสอบผ่าน GitHub UI ที่ Settings → Secrets and variables → Actions

## หมายเหตุ

- Secrets จะถูกซ่อนใน workflow logs
- ไม่สามารถดูค่า secrets ที่ตั้งไว้แล้วได้ สามารถแก้ไขหรือลบเท่านั้น
- แนะนำให้ใช้ Access Token แทน password ทุกครั้งที่เป็นไปได้
- ควร rotate secrets เป็นระยะเพื่อความปลอดภัย

