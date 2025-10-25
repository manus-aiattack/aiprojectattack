# API Reference - dLNk Attack Platform

## 1. Introduction
This document provides a comprehensive reference for the dLNk Attack Platform's REST API and WebSocket protocols.

## 2. Authentication
*   **API Key Authentication:** All API endpoints require an `X-API-Key` header.
*   **JWT Authentication:** Used for the Admin Panel, obtained via `/auth/login`.
*   **Admin vs. User Roles:** Role-based access control for endpoints.

## 3. REST API Endpoints

### 3.1. Authentication Routes (`/api/auth`)
*   **`POST /api/auth/login`**
    *   **Description:** Authenticate with an API Key.
    *   **Request Body:** `LoginRequest` (api_key: string)
    *   **Response:** User details and API key.
*   **`POST /api/auth/verify`**
    *   **Description:** Verify API Key validity.
    *   **Request Body:** `LoginRequest` (api_key: string)
    *   **Response:** `valid: boolean`, user details.
*   **`POST /api/auth/logout`**
    *   **Description:** Placeholder for logout functionality.

### 3.2. Admin Routes (`/api/admin`)
*   **Authentication:** Requires Admin API Key.
*   **`POST /api/admin/keys/create`**
    *   **Description:** Create a new API key (admin or user).
    *   **Request Body:** `CreateKeyRequest` (username, role, quota_limit).
*   **`GET /api/admin/users`**
    *   **Description:** List all users.
*   **`DELETE /api/admin/users/{user_id}`**
    *   **Description:** Delete a user.
*   **`POST /api/admin/users/{user_id}/toggle`**
    *   **Description:** Activate/deactivate a user.
*   **`GET /api/admin/attacks`**
    *   **Description:** List all attacks.
*   **`GET /api/admin/logs/agents`**
    *   **Description:** Retrieve all agent logs.
*   **`GET /api/admin/logs/system`**
    *   **Description:** Retrieve all system logs.
*   **`GET /api/admin/system/status`**
    *   **Description:** Get detailed system status.

### 3.3. Attack Routes (`/api/attack`)
*   **Authentication:** Requires valid API Key.
*   **`POST /api/attack/launch`**
    *   **Description:** Launch an automated attack.
    *   **Request Body:** `AttackRequest` (target_url, attack_mode).
    *   **Response:** `AttackResponse` (attack_id, status, message).
*   **`GET /api/attack/{attack_id}/status`**
    *   **Description:** Get status and progress of an attack.
    *   **Response:** `AttackStatusResponse`.
*   **`GET /api/attack/{attack_id}/vulnerabilities`**
    *   **Description:** Get discovered vulnerabilities for an attack.
    *   **Response:** List of `VulnerabilityResponse`.
*   **`POST /api/attack/{attack_id}/stop`**
    *   **Description:** Stop a running attack.
*   **`GET /api/attack/history`**
    *   **Description:** Get attack history for the current user (or all for admin).
*   **`DELETE /api/attack/{attack_id}`**
    *   **Description:** Delete an attack record.

### 3.4. File Routes (`/api/files`)
*   **Authentication:** Requires valid API Key.
*   **`GET /api/files/{file_id}/download`**
    *   **Description:** Download an exfiltrated file.
*   **`GET /api/files/attack/{attack_id}`**
    *   **Description:** List files associated with an attack.

### 3.5. Monitoring Routes (`/api/metrics`, `/api/health`)
*   **Authentication:** Some require Admin API Key.
*   **`GET /api/metrics/system`**
    *   **Description:** Detailed system metrics (Admin only).
*   **`GET /api/metrics/attacks`**
    *   **Description:** Attack statistics over time.
*   **`GET /api/metrics/success-rate`**
    *   **Description:** Attack success rate.
*   **`GET /api/metrics/vulnerabilities`**
    *   **Description:** Statistics on discovered vulnerabilities.
*   **`GET /api/metrics/data-exfiltrated`**
    *   **Description:** Statistics on exfiltrated data.
*   **`GET /api/health/detailed`**
    *   **Description:** Detailed health check of system components (Admin only).

## 4. WebSocket Protocols

### 4.1. Real-time Attack Updates (`/ws/attack/{attack_id}`)
*   **Purpose:** Stream real-time updates about a specific attack.
*   **Authentication:** (Currently insecure, needs token-based authentication).
*   **Messages:** JSON objects with `type`, `status`, `timestamp`, `attack_id`, etc.

### 4.2. System Monitoring (`/ws/system`)
*   **Purpose:** Stream real-time system metrics and status (Admin only).
*   **Authentication:** API Key in query parameter (insecure, needs token-based authentication).
*   **Messages:** JSON objects with `type`, `data` (system status), `timestamp`.

### 4.3. Log Stream (`/ws/logs`)
*   **Purpose:** Stream real-time application logs.
*   **Authentication:** (Implicitly handled by API key for initial connection, but needs explicit WebSocket auth).
*   **Messages:** JSON objects representing log entries.

## 5. Data Models (Pydantic)
*   **`LoginRequest`:** `api_key: str`
*   **`CreateKeyRequest`:** `username: str`, `role: str`, `quota_limit: int`
*   **`AttackRequest`:** `target_url: HttpUrl`, `attack_mode: str`
*   **`AttackResponse`:** `attack_id: str`, `target_url: str`, `status: str`, `message: str`
*   **`AttackStatusResponse`:** `attack_id: str`, `target_url: str`, `status: str`, `progress: int`, etc.
*   **`VulnerabilityResponse`:** `id: str`, `attack_id: str`, `vuln_type: str`, `severity: str`, etc.
*   **`APIKeyInfo`:** (Used internally by middleware for API key details).

## 6. Error Codes
*   `401 Unauthorized`: Missing or invalid API Key.
*   `403 Forbidden`: Insufficient permissions.
*   `404 Not Found`: Resource not found.
*   `429 Too Many Requests`: Rate limit exceeded.
*   `500 Internal Server Error`: Unexpected server error.