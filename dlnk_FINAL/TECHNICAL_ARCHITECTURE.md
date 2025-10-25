# Technical Architecture Document - dLNk Attack Platform

## 1. Introduction
This document provides a comprehensive overview of the dLNk Attack Platform's technical architecture, detailing its components, their interactions, and underlying design principles.

## 2. High-Level Architecture
*   **Layered Architecture:** Overview of API, Service, Core, and Agent layers.
*   **Key Design Patterns:** Orchestrator, Strategy, Factory, Registry, PubSub.
*   **Data Flow & Control Flow:** High-level diagram and explanation of how data and control signals move through the system.

## 3. Component Deep Dive

### 3.1. API Layer (FastAPI)
*   **Entry Point:** `api/main.py`
*   **Routes:** `api/routes/auth_routes.py`, `api/routes/admin.py`, `api/routes/admin_v2.py`, `api/routes/attack.py`, `api/routes/attack_v2.py`, `api/routes/files.py`, `api/routes/monitoring.py`.
*   **Middleware:** CORS, Authentication (`api/middleware/auth_middleware.py`), Rate Limiting (`api/middleware/rate_limiter.py`).
*   **WebSocket Endpoints:** Real-time attack updates, system monitoring.

### 3.2. Core Layer
*   **Orchestrator (`core/orchestrator.py`):**
    *   AI-driven campaign management.
    *   Integration with Agent Registry, Context Manager, PubSub Manager.
    *   Workflow execution.
    *   AI learning and adaptation.
*   **AI Planner (`core/enhanced_ai_planner.py`):**
    *   Attack plan generation (LLM-driven and rule-based).
    *   Adaptive replanning.
    *   Target intelligence integration.
*   **AI Attack Strategist (`core/ai_attack_strategist.py`):**
    *   Autonomous decision-making for adaptive strategies.
    *   Target profiling, vulnerability prediction.
    *   Adaptive payload generation.
    *   Learning from attack outcomes.
*   **Agent Registry (`core/agent_registry.py`):**
    *   Agent auto-discovery and registration.
    *   Agent instantiation and caching.
*   **Context Manager (`core/context_manager.py`):**
    *   Shared context data using Redis.
    *   Concurrency control and real-time updates.
*   **PubSub Manager (`core/pubsub_manager.py`):**
    *   Redis-based publish/subscribe messaging.
    *   Inter-component communication.
*   **Workflow Executor (`core/enhanced_workflow_executor.py`):**
    *   Execution of YAML-defined attack workflows.
    *   Conditional execution, parallel agents, failure handling.
    *   Variable substitution.
*   **LLM Providers (`core/llm_provider.py`, `llm_config.py`):**
    *   Integration with Ollama and local LLMs (via `transformers`).
    *   Timeout handling, retries, JSON parsing.
*   **Database Services:** `api/services/database_simple.py` (SQLite for dev), `api/services/database.py` (PostgreSQL for prod - *Note: This file was removed during analysis, needs to be restored or clarified*).

### 3.3. Agent Layer
*   **Base Agent (`core/base_agent.py`):** Abstract base class for all agents, defining common interface, error handling, and retry logic.
*   **Agent Categories:**
    *   **Active Directory:** Kerberoasting, DCSync, Golden Ticket, etc.
    *   **Cloud:** AWS, Azure, GCP specific agents.
    *   **Evasion:** AMSI Bypass, EDR Detection, Obfuscation, etc.
    *   **Mobile:** Android, iOS specific agents.
    *   **Web Application:** SQLi, XSS, SSRF, LFI, File Upload, etc.
    *   **Post-Exploitation:** Privilege Escalation, Lateral Movement, Persistence, Data Exfiltration.
    *   **AI/Orchestration Support:** Reporting, Self-Repair, Tool Manager, Triage.
*   **Weaponized Agents:** Variants with advanced exploitation techniques.

### 3.4. Data Exfiltration System
*   **Data Exfiltrator (`data_exfiltration/exfiltrator.py`):** Comprehensive system for dumping databases, scanning/downloading files, harvesting credentials.
*   **Data Exfiltration Agents (`agents/data_exfiltration_agent.py`, `agents/advanced_data_exfiltration_agent.py`):** Agents for staged data transfer and covert multi-channel exfiltration.

## 4. Data Management
*   **Database:** PostgreSQL (production schema in `api/database/schema.sql`), SQLite (development).
*   **Redis:** Used for caching, context management, pub/sub, distributed task queuing, and learning data storage.
*   **Data Models (`core/data_models.py`):** Centralized definitions for various data structures (Strategy, AgentData, TargetProfile, AttackDecision, etc.).

## 5. Deployment Architecture
*   **Single-Node (Docker Compose):** `docker-compose.yml` for local development/testing.
*   **Distributed (Docker Compose):** `docker-compose.distributed.yml` for production-grade, scalable deployment with microservices, API Gateway, Prometheus, Grafana.
*   **Kubernetes (k8s/):** Manifests for Kubernetes deployment.

## 6. Security Considerations
*   **Authentication:** API Key-based, JWT (for admin panel).
*   **Authorization:** Role-based access control (admin vs. user).
*   **Input Validation:** Pydantic models, custom validators.
*   **Secrets Management:** Environment variables, Docker Compose secrets, Kubernetes Secrets.
*   **CORS:** Configurable (needs tightening in production).
*   **Rate Limiting:** Implemented via middleware.
*   **Secure Coding Practices:** (To be detailed in Security Whitepaper).

## 7. Performance & Scalability
*   **Asynchronous Programming:** `asyncio` throughout for non-blocking I/O.
*   **Concurrency:** `asyncio.gather` for parallel agent execution.
*   **Caching:** Extensive use of Redis.
*   **Distributed Architecture:** Microservices, task queuing (Redis), horizontal scaling.
*   **LLM Optimization:** `float16` for local LLMs, GPU support.

## 8. Future Enhancements
*   Integration of advanced ML models for learning.
*   More sophisticated WAF/EDR evasion techniques.
*   Improved real-time reporting and visualization.
*   Enhanced self-healing and self-adaptation capabilities.

## 9. Diagrams
*   System Architecture Diagram (Mermaid)
*   Data Flow Diagram (Mermaid)
*   Component Interaction Diagram (Mermaid)
*   Deployment Architecture Diagram (Mermaid)