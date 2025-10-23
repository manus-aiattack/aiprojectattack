'''# dLNk dLNk: Autonomous Penetration Testing Framework

![dLNk dLNk Logo](https://raw.githubusercontent.com/dlnkdlnk/framework/main/docs/assets/logo.png) <!-- Placeholder -->

## Overview

**dLNk dLNk** is an advanced, autonomous penetration testing framework designed to automate and streamline the process of identifying and exploiting vulnerabilities. Leveraging a modular agent-based architecture, a dynamic workflow engine, and real-time collaboration features, the framework can intelligently execute complex attack strategies with minimal human intervention.

This enhanced version focuses on performance, real-time feedback, and developer extensibility, providing security professionals with a powerful and efficient tool to continuously assess their security posture.

## Key Enhancements

*   **Live Web Dashboard**: A real-time web interface to monitor ongoing operations, view live-streamed logs, and inspect results as they happen.
*   **Real-time Logging**: Logs are now streamed via WebSockets for immediate feedback during agent and workflow execution.
*   **Optimized Performance**: Core components like the `ContextManager` and `RedisClient` have been optimized with connection pooling and pipeline commands to reduce latency and improve throughput.
*   **Enhanced Agent & Workflow Structure**: The agent discovery mechanism has been improved, and the workflow engine is more robust in handling different phases.
*   **Comprehensive Automated Testing**: A full suite of `pytest` tests has been developed for the core orchestrator, ensuring stability and reliability.
*   **Developer-Focused Documentation**: A new `DEVELOPER_GUIDE.md` provides clear instructions for extending the framework and creating new agents.

## Features

*   **Modular Agent Architecture**: A wide array of specialized agents for reconnaissance, exploitation, and reporting.
*   **Dynamic Workflow Engine**: Define and execute complex attack workflows using simple YAML configurations.
*   **Centralized Context Management**: A Redis-backed context manager allows agents to share state and intelligence.
*   **Real-time Event Bus**: A Pub/Sub system for inter-agent communication and real-time event handling.
*   **Dual Interfaces**: A powerful Command-Line Interface (CLI) for automation and a RESTful API for integration.
*   **Containerized & Reproducible**: Packaged with Docker and Docker Compose for easy, consistent deployment.

## Architecture

The framework's architecture is centered around a core `Orchestrator` that coordinates several key components:

*   **Agent Registry**: Automatically discovers and manages all available agents.
*   **Context Manager**: Manages the shared state and data between agents using an optimized Redis backend.
*   **Pub/Sub Manager**: Facilitates real-time communication and event streaming (e.g., live logs) between the backend and clients.
*   **Workflow Executor**: Parses and executes the steps defined in YAML workflow files.
*   **API & CLI**: Provide user-facing interfaces for interaction and control.
*   **Web Dashboard**: A Vue.js-based single-page application for real-time monitoring.

## Installation

### Using Docker Compose (Recommended)

1.  **Clone the repository** and navigate into the directory.
2.  **Configure Environment**: Copy `.env.example` to `.env` and add your API keys (e.g., `OPENAI_API_KEY`).
3.  **Build and Run**:
    ```bash
    docker-compose up --build -d
    ```
4.  **Access the Framework**:
    *   **Web Dashboard**: `localhost:8000/dashboard`
    *   **API (Swagger UI)**: `localhost:8000/docs`

## Usage

### Web Dashboard

Navigate to `localhost:8000/dashboard` to see the live dashboard. From here, you can monitor running workflows and see logs stream in real-time.

### Command-Line Interface (CLI)

The `dlnk-dlnk` command is the primary entry point for terminal-based operations.

*   **Run a workflow**:
    ```bash
    dlnk-dlnk run --workflow config/default_workflow.yaml --target localhost:8000
    ```

*   **List all available agents**:
    ```bash
    dlnk-dlnk agents
    ```

*   **Execute a single agent**:
    ```bash
    dlnk-dlnk agent --agent NmapScanAgent --directive "Scan all TCP ports" --context '{"target_ip": "192.168.1.1"}'
    ```

### RESTful API

The API provides programmatic control over the framework. See the Swagger UI at `localhost:8000/docs` for a full list of endpoints.

*   **Execute Workflow**: `POST /workflows/execute`
*   **Live Log Stream**: `WS /ws/logs`

## Development & Contribution

We welcome contributions that enhance the capabilities and efficiency of dLNk dLNk. Whether it's a new agent, a performance improvement, or a bug fix, your input is valuable.

**Please read our [Developer Guide](./docs/DEVELOPER_GUIDE.md) to get started.** It contains detailed information on the project structure, how to create new agents, and best practices for development.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
'''
