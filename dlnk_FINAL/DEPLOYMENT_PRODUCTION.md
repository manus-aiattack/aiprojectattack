# Production Deployment Guide - dLNk Attack Platform

## 1. Introduction
This guide provides instructions for deploying the dLNk Attack Platform in a production environment, focusing on security, scalability, and reliability.

## 2. Prerequisites
*   **Hardware:**
    *   Minimum 4 CPU Cores, 16GB RAM (for basic setup).
    *   Dedicated GPU (NVIDIA recommended) for AI Planner service.
    *   Sufficient disk space for data, logs, and LLM models.
*   **Software:**
    *   Docker Engine (latest stable version).
    *   Docker Compose (latest stable version).
    *   `git`.
    *   (Optional) Kubernetes cluster for advanced deployments.
*   **Network:**
    *   Public IP address or domain name for API Gateway.
    *   Firewall configured to allow necessary inbound/outbound traffic.

## 3. Security Best Practices (Critical)
*   **Change All Default Passwords:** Immediately replace all placeholder passwords in `.env.production` and Grafana with strong, unique, randomly generated values.
*   **Secure `SECRET_KEY`:** Generate a long, random `SECRET_KEY` (minimum 32 characters) for JWTs and other cryptographic operations.
*   **Restrict CORS:** Configure the API Gateway and application services to only allow requests from trusted origins.
*   **Secrets Management:** Use a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets) for all sensitive credentials.
*   **Network Segmentation:** Implement strict network policies to isolate services and restrict communication to only what is necessary.
*   **Firewall Rules:** Configure host and cloud firewalls to expose only the API Gateway ports (e.g., 80/443) to the internet.
*   **Regular Updates:** Keep all system software, Docker images, and application dependencies up-to-date.
*   **Monitoring & Alerting:** Set up comprehensive monitoring and alerting for system health, security events, and performance anomalies.

## 4. Deployment Steps (Distributed with Docker Compose)

### 4.1. Prepare Environment
1.  **Clone Repository:** `git clone [repository_url]`
2.  **Navigate to Project Directory:** `cd dlnk_FINAL`
3.  **Create `.env.production`:** Copy `env.template` to `.env.production`.
    ```bash
    cp env.template .env.production
    ```
4.  **Edit `.env.production`:**
    *   **Generate Strong Secrets:** Use `openssl rand -base64 32` or similar to generate values for `SECRET_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, `LICENSE_SECRET_KEY`.
    *   Configure `OLLAMA_HOST` (if using external Ollama server).
    *   Configure notification channels (SMTP, Telegram, Discord).
    *   Set `API_DEBUG=False`.
    *   Set `GF_SECURITY_ADMIN_PASSWORD` for Grafana.

### 4.2. Build and Deploy Services
1.  **Build Docker Images:**
    ```bash
    docker-compose -f docker-compose.distributed.yml build
    ```
2.  **Start Services:**
    ```bash
    docker-compose -f docker-compose.distributed.yml up -d
    ```
3.  **Verify Services:**
    ```bash
    docker-compose -f docker-compose.distributed.yml ps
    ```
    Ensure all services are `Up` and `healthy`.

### 4.3. Initial Setup
1.  **Access Grafana:** Navigate to `http://localhost:3000` (or your server's IP). Log in with `admin` and the password set in `GF_SECURITY_ADMIN_PASSWORD`.
2.  **Configure Grafana Data Sources:** Add Prometheus as a data source.
3.  **Import Grafana Dashboards:** Import pre-built dashboards for monitoring (if available).

## 5. Deployment Steps (Kubernetes)

### 5.1. Prepare Kubernetes Secrets
1.  **Create Secrets:** Use `kubectl create secret generic` to create secrets for `DB_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, `LICENSE_SECRET_KEY`, `OPENAI_API_KEY`, etc.
    ```bash
    kubectl create secret generic dlnk-postgres-secret --from-literal=password='YOUR_DB_PASSWORD'
    kubectl create secret generic dlnk-redis-secret --from-literal=password='YOUR_REDIS_PASSWORD'
    # ... create other secrets ...
    ```
2.  **SSL Certificates:** Create Kubernetes Secret for TLS certificates for the API Gateway.

### 5.2. Deploy Manifests
1.  **Apply Deployments:**
    ```bash
    kubectl apply -f k8s/
    ```
2.  **Verify Deployment:**
    ```bash
    kubectl get pods -n dlnk-namespace
    kubectl get services -n dlnk-namespace
    ```

## 6. Monitoring and Maintenance
*   **Prometheus & Grafana:** Monitor system health, resource utilization, and application metrics.
*   **Log Management:** Centralize logs for all services for easier debugging and auditing.
*   **Backup Strategy:** Implement regular backups for PostgreSQL and Redis data volumes.
*   **Updates:** Follow the update procedure for new versions of the dLNk Attack Platform.

## 7. Scaling
*   **Docker Compose:** Adjust `deploy.replicas` in `docker-compose.distributed.yml` for services.
*   **Kubernetes:** Adjust `replicas` in deployment manifests or use Horizontal Pod Autoscalers.

## 8. Troubleshooting Production Issues
*   Refer to `OPERATIONS_MANUAL_TH.md` for common troubleshooting steps.
*   Check container logs, Prometheus metrics, and Grafana dashboards.
