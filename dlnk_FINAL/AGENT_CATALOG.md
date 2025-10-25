# Agent Catalog - dLNk Attack Platform

## 1. Introduction
This catalog provides an overview of all available agents within the dLNk Attack Platform, categorized by their primary function and target environment.

## 2. Agent Structure
All agents inherit from `core/base_agent.py` and implement the `run` method. They interact with the `ContextManager` (Redis) for shared state and report results using `AgentData` models.

## 3. Agent Categories

### 3.1. Active Directory Agents
*   **Purpose:** Agents designed to enumerate, exploit, and maintain access within Windows Active Directory environments.
*   **Agents:**
    *   `adcs_agent.py`: Active Directory Certificate Services (AD CS) exploitation.
    *   `asreproasting_agent.py`: AS-REPRoasting attacks.
    *   `bloodhound_agent.py`: Collects data for BloodHound analysis.
    *   `constrained_delegation_agent.py`: Exploits constrained delegation.
    *   `dcsync_agent.py`: Performs DCSync attacks to extract password hashes.
    *   `golden_ticket_agent.py`: Generates Golden Tickets for Kerberos authentication.
    *   `kerberoasting_agent.py`: Extracts and cracks service account passwords.
    *   `pass_the_hash_agent.py`: Performs Pass-the-Hash attacks.
    *   `pass_the_ticket_agent.py`: Performs Pass-the-Ticket attacks.
    *   `zerologon_agent.py`: Exploits the ZeroLogon vulnerability.

### 3.2. Cloud Agents
*   **Purpose:** Agents targeting cloud service providers (AWS, Azure, GCP) for enumeration, privilege escalation, and resource exploitation.
*   **AWS Agents:**
    *   `iam_privesc_agent.py`: AWS IAM privilege escalation.
    *   `lambda_exploit_agent.py`: Exploits AWS Lambda functions.
    *   `rds_exploit_agent.py`: Exploits AWS RDS instances.
    *   `s3_enumeration_agent.py`: Enumerates AWS S3 buckets.
    *   `secrets_manager_agent.py`: Extracts secrets from AWS Secrets Manager.
*   **Azure Agents:**
    *   `ad_enumeration_agent.py`: Azure AD enumeration.
    *   `ad_privesc_agent.py`: Azure AD privilege escalation.
    *   `blob_storage_agent.py`: Exploits Azure Blob Storage.
    *   `keyvault_agent.py`: Extracts secrets from Azure Key Vault.
    *   `vm_exploit_agent.py`: Exploits Azure Virtual Machines.
*   **GCP Agents:**
    *   `cloud_functions_agent.py`: Exploits GCP Cloud Functions.
    *   `compute_engine_agent.py`: Exploits GCP Compute Engine instances.
    *   `iam_privesc_agent.py`: GCP IAM privilege escalation.
    *   `secret_manager_agent.py`: Extracts secrets from GCP Secret Manager.
    *   `storage_bucket_agent.py`: Enumerates GCP Storage Buckets.

### 3.3. Evasion Agents
*   **Purpose:** Agents focused on bypassing security controls and evading detection by EDR, AV, and other defensive mechanisms.
*   **Agents:**
    *   `amsi_bypass_agent.py`: Bypasses AMSI (Antimalware Scan Interface).
    *   `direct_syscall_agent.py`: Uses direct syscalls for evasion.
    *   `edr_detection_agent.py`: Detects EDR solutions.
    *   `etw_bypass_agent.py`: Bypasses Event Tracing for Windows (ETW).
    *   `memory_only_execution_agent.py`: Executes payloads in memory only.
    *   `obfuscation_agent.py`: Obfuscates payloads and commands.
    *   `parent_process_spoofing_agent.py`: Spoofs parent process IDs.
    *   `polymorphic_payload_agent.py`: Generates polymorphic payloads.
    *   `process_injection_agent.py`: Injects code into other processes.
    *   `sandbox_detection_agent.py`: Detects sandbox environments.
    *   `signed_binary_proxy_agent.py`: Uses signed binaries as proxies.
    *   `unhooking_agent.py`: Unhooks API calls.

### 3.4. Mobile Agents
*   **Purpose:** Agents for analyzing and exploiting vulnerabilities in mobile applications (Android and iOS).
*   **Android Agents:**
    *   `apk_analysis_agent.py`: Static analysis of Android APKs.
    *   `data_extraction_agent.py`: Extracts data from Android devices.
    *   `dynamic_analysis_agent.py`: Dynamic analysis of Android apps.
    *   `intent_exploit_agent.py`: Exploits Android Intents.
    *   `root_detection_bypass_agent.py`: Bypasses root detection.
    *   `ssl_pinning_bypass_agent.py`: Bypasses SSL pinning.
*   **iOS Agents:**
    *   `dynamic_analysis_agent.py`: Dynamic analysis of iOS apps.
    *   `ipa_analysis_agent.py`: Static analysis of iOS IPA files.
    *   `jailbreak_detection_bypass_agent.py`: Bypasses jailbreak detection.
    *   `ssl_pinning_bypass_agent.py`: Bypasses SSL pinning.

### 3.5. Web Application Agents
*   **Purpose:** Agents targeting web applications for reconnaissance, vulnerability detection, and exploitation.
*   **Agents:**
    *   `dirsearch_agent.py`: Directory brute-forcing.
    *   `file_upload_agent.py`: Exploits file upload vulnerabilities.
    *   `fuzzing_agent.py`: Generic web fuzzing.
    *   `hydra_agent.py`: Brute-forces web login forms.
    *   `idor_agent.py` / `idor_agent_enhanced.py`: Detects and exploits Insecure Direct Object References (IDOR).
    *   `lfi_agent.py`: Detects and exploits Local File Inclusion (LFI).
    *   `nuclei_agent.py`: Runs Nuclei templates for vulnerability scanning.
    *   `rce_agent.py`: Detects and exploits Remote Code Execution (RCE).
    *   `skipfish_agent.py`: Web application scanner.
    *   `sqlmap_agent.py`: Detects and exploits SQL Injection (SQLi).
    *   `ssrf_agent.py` / `ssrf_agent_weaponized.py`: Detects and exploits Server-Side Request Forgery (SSRF).
    *   `waf_detector_agent.py`: Detects Web Application Firewalls (WAFs).
    *   `web_crawler_agent.py`: Crawls web applications to discover endpoints.
    *   `wpscan_agent.py`: Scans WordPress installations for vulnerabilities.
    *   `xss_agent.py`: Detects and exploits Cross-Site Scripting (XSS).
    *   `xxe_agent.py`: Detects and exploits XML External Entity (XXE) vulnerabilities.

### 3.6. Post-Exploitation & Privilege Escalation Agents
*   **Purpose:** Agents for maintaining access, escalating privileges, and performing actions on compromised systems.
*   **Agents:**
    *   `advanced_backdoor_agent.py`: Deploys advanced backdoors.
    *   `advanced_c2_agent.py`: Establishes advanced Command and Control (C2).
    *   `data_dumper_agent.py`: Dumps various types of data from compromised hosts.
    *   `data_exfiltration_agent.py` / `advanced_data_exfiltration_agent.py`: Exfiltrates collected data.
    *   `enhanced_privilege_escalation_agent.py`: Advanced privilege escalation techniques.
    *   `lateral_movement_agent.py`: Moves laterally within a network.
    *   `living_off_the_land_agent.py`: Uses legitimate system tools for offensive operations.
    *   `persistence_agent.py`: Establishes persistence mechanisms.
    *   `post_ex_agent.py`: Generic post-exploitation tasks.
    *   `privilege_escalation_agent.py` / `privilege_escalation_agent_weaponized.py`: Standard privilege escalation.
    *   `shell_upgrader_agent.py` / `shell_upgrader_agent_weaponized.py`: Upgrades shells to fully interactive TTYs.

### 3.7. Credential Attack Agents
*   **Purpose:** Agents for harvesting, cracking, and utilizing credentials.
*   **Agents:**
    *   `credential_harvester_agent.py`: Harvests credentials from various sources.
    *   `credential_parser_agent.py`: Parses collected data for credentials.
    *   `intelligent_credential_attack_agent.py`: Intelligent credential brute-forcing/stuffing.

### 3.8. AI/Orchestration Support Agents
*   **Purpose:** Agents that support the AI-driven orchestration and decision-making process.
*   **Agents:**
    *   `afl_agent.py`: Integrates AFL (American Fuzzy Lop) for fuzzing.
    *   `api_fuzzer_agent.py`: Fuzzes APIs.
    *   `bot_deployment_agent.py`: Deploys bots/implants.
    *   `code_writer_agent.py`: AI-driven code generation.
    *   `crash_analyzer_agent.py`: Analyzes crash dumps from fuzzing.
    *   `dashboard_agent.py`: Provides data for the dashboard.
    *   `defensive_countermeasures_agent.py`: (Potentially for testing defensive measures or understanding them).
    *   `doh_test_agent.py`: Tests DNS over HTTPS (DoH) capabilities.
    *   `exploit_database_agent.py`: Searches exploit databases.
    *   `health_check_agent.py`: Performs system health checks.
    *   `meta_cognition_agent.py`: AI for self-reflection and learning.
    *   `metasploit_agent.py`: Integrates with Metasploit Framework.
    *   `nmap_parser_agent.py`: Parses Nmap scan results.
    *   `parser_dirsearch_agent.py`: Parses Dirsearch results.
    *   `parser_feroxbuster_agent.py`: Parses Feroxbuster results.
    *   `payload_generator_agent.py`: Generates various payloads.
    *   `proxy_agent.py`: Manages proxy configurations.
    *   `query_synthesizer_agent.py`: Synthesizes queries for intelligence gathering.
    *   `rate_limit_agent.py` / `rate_limit_agent_weaponized.py`: Tests and bypasses rate limits.
    *   `reporting_agent.py`: Generates attack reports.
    *   `resource_manager_agent.py`: Manages system resources.
    *   `self_repair_agent.py`: AI for self-healing and error recovery.
    *   `shell_agent.py`: Manages shell interactions.
    *   `symbolic_executor_agent.py`: Uses symbolic execution for vulnerability discovery.
    *   `target_acquisition_agent.py`: Identifies and prioritizes targets.
    *   `technology_profiler_agent.py`: Profiles target technology stacks.
    *   `tool_manager_agent.py`: Manages external tools.
    *   `triage_agent.py`: Prioritizes vulnerabilities.
    *   `vulnerability_mapping_agent.py`: Maps vulnerabilities to attack paths.
    *   `vulnerability_scan_agent.py`: Generic vulnerability scanning.
    *   `waf_bypass_agent_weaponized.py`: Advanced WAF bypass techniques.
    *   `zero_day_hunter_agent.py` / `zero_day_hunter_weaponized.py`: AI-driven zero-day discovery.

## 4. Agent Development Guidelines
*   Refer to `DEVELOPER_GUIDE_COMPLETE.md` for instructions on creating and integrating new agents.
