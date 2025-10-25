# Developer Guide - dLNk Attack Platform

## 1. Introduction
This guide provides developers with the necessary information to understand, modify, and extend the dLNk Attack Platform.

## 2. Project Setup

### 2.1. Prerequisites
*   Python 3.11+
*   Docker & Docker Compose
*   Git
*   (Optional) NVIDIA GPU with CUDA for local LLM acceleration

### 2.2. Local Development Environment
*   **Cloning the Repository:** `git clone [repository_url]`
*   **Virtual Environment Setup:**
    *   `python3 -m venv venv`
    *   `source venv/bin/activate`
    *   `pip install -r requirements.txt`
*   **Docker Compose (Single-Node):**
    *   `docker-compose up --build`
    *   Accessing services (API, Ollama, PostgreSQL, Redis).
*   **Environment Variables:** Explanation of `.env` file and critical variables (e.g., `SECRET_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`).

## 3. Codebase Structure
*   **`api/`:** FastAPI application, routes, services, middleware.
*   **`core/`:** Core logic, orchestrator, AI planner, context management, LLM providers.
*   **`agents/`:** Individual attack agents, categorized by type (AD, Cloud, Evasion, Mobile, Web).
*   **`data_exfiltration/`:** Data exfiltration modules.
*   **`config/`:** Application settings, workflow definitions.
*   **`workflows/`:** YAML definitions for attack chains.
*   **`tests/`:** Test files.
*   **`web/`:** Frontend dashboard and admin panel HTML/CSS/JS.
*   **`docker/`:** Dockerfiles for distributed services.

## 4. Core Concepts

### 4.1. Orchestrator
*   Role in managing attack campaigns.
*   Interaction with agents and AI planner.

### 4.2. Agents
*   **`BaseAgent`:** How to create a new agent.
*   **Agent Lifecycle:** Setup, run, reporting.
*   **Context Management:** How agents interact with `ContextManager` (Redis).
*   **Agent Registry:** How agents are discovered and registered.

### 4.3. AI Planning
*   Role of `EnhancedAIPlanner` and `AIAttackStrategist`.
*   LLM integration for decision-making and payload generation.
*   Learning from attack outcomes.

### 4.4. Workflows
*   YAML structure for defining attack chains.
*   Conditional execution, parallel agents, failure handling.
*   Variable substitution.

### 4.5. Data Models
*   Understanding `core/data_models.py` (Strategy, AgentData, TargetProfile, etc.).

## 5. Extending the Framework

### 5.1. Adding a New Agent
*   **Steps:** Create new file, inherit `BaseAgent`, implement `run` method.
*   **Dependencies:** Specifying `required_tools`.
*   **Integration:** How the agent is discovered by `AgentRegistry`.

### 5.2. Creating a New Workflow
*   **YAML Structure:** Defining phases, agents, conditions, failure handling.
*   **Testing:** How to test new workflows.

### 5.3. Integrating a New LLM Provider
*   Implementing `BaseLLMProvider` interface.
*   Updating `llm_config.py`.

### 5.4. Adding a New Exfiltration Channel
*   Extending `DataExfiltrator` or `AdvancedDataExfiltrationAgent`.

## 6. Testing Guidelines
*   **Unit Tests:** Writing tests for individual components (using `pytest`).
*   **Integration Tests:** Testing interactions between components.
*   **End-to-End Tests:** Simulating full attack campaigns.
*   **Mocking:** Best practices for mocking external dependencies.

## 7. Debugging
*   Logging configuration (`core/logger.py`).
*   Using `API_DEBUG` environment variable.
*   Inspecting Redis data for context and state.

## 8. Code Style & Quality
*   **`flake8`:** Adhering to PEP 8 guidelines (max line length 120).
*   **`mypy`:** Type hinting best practices.
*   **`bandit`:** Security linting.
*   **Docstrings:** Writing clear and concise docstrings.

## 9. Contributing
*   Contribution guidelines.
*   Pull request process.

## 10. Troubleshooting
*   Common issues and their resolutions.
*   Debugging tips.