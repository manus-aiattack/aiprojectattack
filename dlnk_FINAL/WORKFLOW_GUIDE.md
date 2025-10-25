# Workflow Guide - dLNk Attack Platform

## 1. Introduction
This guide explains how to define, execute, and manage attack workflows within the dLNk Attack Platform. Workflows orchestrate multiple agents into coordinated attack chains.

## 2. Workflow Structure (YAML)
Workflows are defined using YAML files, typically located in `config/*.yaml` for general workflows and `workflows/attack_chains/*.yaml` for complex, multi-phase attack scenarios.

### 2.1. Top-Level Structure
```yaml
workflow_name: "My Custom Attack"
description: "A detailed description of what this workflow does."
version: "1.0"
success_criteria:
  minimum_requirements:
    - "phase_reconnaissance.success is not empty"
  optimal_requirements:
    - "phase_exploitation.access_gained == true"
phases:
  # List of phases
  - name: "Reconnaissance"
    # ... phase details ...
  - name: "Exploitation"
    # ... phase details ...
```

### 2.2. Phase Definition
Each phase is a dictionary with the following keys:
*   **`name` (string, required):** Unique name for the phase.
*   **`description` (string, optional):** A brief description of the phase.
*   **`condition` (string, optional):** A condition that must evaluate to `true` for the phase to execute. (See Condition Evaluation below).
*   **`always_run` (boolean, optional):** If `true`, the phase will always run, even if previous phases failed. Defaults to `false`.
*   **`on_failure` (object, optional):** Defines actions to take if the phase fails.
    *   **`action` (string):** `abort`, `retry`, `fallback`. Defaults to `abort`.
    *   **`max_retries` (integer, optional):** Number of times to retry the phase if `action` is `retry`.
    *   **`fallback_agents` (list of strings, optional):** List of agent names to use if `action` is `fallback`.
*   **`agents` (list of objects, required):** List of agents to execute within this phase.

### 2.3. Agent Definition within a Phase
Each agent within a phase is a dictionary with the following keys:
*   **`name` (string, required):** The name of the agent (as registered in `AgentRegistry`).
*   **`description` (string, optional):** Description of the agent's role in this phase.
*   **`condition` (string, optional):** Condition for this specific agent to execute.
*   **`parallel` (boolean, optional):** If `true`, this agent will run in parallel with other parallel agents in the same phase. Defaults to `false`.
*   **`depends_on` (list of strings, optional):** List of agent names within the *same phase* that must succeed before this agent runs (only for sequential agents).
*   **`config` (object, optional):** A dictionary of configuration parameters to pass to the agent's `run` method. Supports variable substitution.
*   **`outputs` (list of strings, optional):** List of output variables from the agent's result to be stored in the workflow context.

## 3. Condition Evaluation
Conditions are simple string expressions evaluated against the current `WorkflowContext` (variables, phase results, target information).

### 3.1. Supported Operators/Keywords
*   `is not empty`: Checks if a variable is not empty (e.g., `phase_reconnaissance.output.vulnerabilities is not empty`).
*   `contains`: Checks if a string or list contains a value (e.g., `target.technologies contains 'nginx'`).
*   `==`: Equality check (e.g., `phase_exploitation.access_gained == true`).
*   Direct variable name: Checks if a variable exists and is truthy (e.g., `target.waf_detected`).

### 3.2. Accessing Context Variables
Variables can be accessed using dot notation:
*   `context.variables.my_var`
*   `context.phase_results.phase_name.agent_results.agent_name.success`
*   `context.target.url`

## 4. Variable Substitution
Agent `config` parameters can use `{variable_name}` syntax to dynamically inject values from the `WorkflowContext`.

**Example:**
```yaml
  - name: "SQLMapAgent"
    config:
      target_url: "{target.url}/vulnerable_endpoint?id={context.variables.vulnerable_param}"
      payload_level: 3
```

## 5. Executing Workflows
Workflows are executed via the API endpoint `POST /api/workflows/execute` or through the Orchestrator directly.

## 6. Example Workflows

### 6.1. `config/attack_full_auto_workflow.yaml`
(Brief description of this workflow)

### 6.2. `workflows/attack_chains/web_full_compromise.yaml`
(Brief description of this complex attack chain)

## 7. Best Practices
*   Keep phases focused on a single objective.
*   Use conditions to create adaptive and intelligent workflows.
*   Leverage parallel execution for independent tasks.
*   Define clear `success_criteria` for each workflow.
*   Document each workflow thoroughly.

## 8. Troubleshooting Workflows
*   Check agent logs for failures.
*   Verify condition syntax.
*   Inspect `WorkflowContext` variables during debugging.
