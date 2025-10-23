import logging
from typing import List
from core.logger import log
from core.data_models import PrivilegeEscalationReport, Strategy, PrivilegeEscalationVector, PostExFinding, AttackPhase, ErrorType
import json
import time
from core.context_manager import ContextManager # Import ContextManager

from core.base_agent import BaseAgent


class PrivilegeEscalationAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = []
    """
    An agent that analyzes post-exploitation data to find privilege escalation vectors.
    """

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.report_class = PrivilegeEscalationReport

    async def run(self, strategy: Strategy, **kwargs) -> PrivilegeEscalationReport:
        """
        Analyzes the PostExReport to find potential privilege escalation vectors.
        """
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return PrivilegeEscalationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Missing shell_id in context"],
                error_type=ErrorType.CONFIGURATION,
                summary="Privilege escalation analysis failed: Missing shell ID."
            )

        post_ex_report = await self.context_manager.get_context('post_ex_report') # Fetch from context_manager
        if not post_ex_report:
            end_time = time.time()
            return PrivilegeEscalationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["PostExReport not found in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Privilege escalation analysis failed: PostExReport not found."
            )

        log.info(
            f"[PrivilegeEscalationAgent] Analyzing post-exploitation data for shell {shell_id}.")

        vectors = []
        for finding in post_ex_report.analysis: # Use post_ex_report
            if finding.type == "suid_binary":
                vector = await self._analyze_suid_binary(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "writable_directory":
                vector = await self._analyze_writable_directory(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "unquoted_service_path":
                vector = await self._analyze_unquoted_service_path(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "sudo_nopasswd":
                vector = self._analyze_sudo_nopasswd(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "always_install_elevated":
                vector = self._analyze_always_install_elevated(finding)
                if vector:
                    vectors.append(vector)

        summary = f"Found {len(vectors)} potential privilege escalation vectors."
        log.success(f"[PrivilegeEscalationAgent] {summary}")
        end_time = time.time()
        return PrivilegeEscalationReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            potential_vectors=vectors,
            summary=summary
        )

    async def _analyze_suid_binary(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes a SUID binary finding to see if it can be used for privilege escalation."""
        binary_path = finding.description.split(": ")[-1]
        binary_name = binary_path.split("/")[-1]

        # Check GTFOBins
        # In a real implementation, this would be a more robust check, perhaps using an API or a local copy.
        gtfobins_url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
        # This is a placeholder for a web fetch call
        # For now, we'll just assume that if it's a common binary, it's exploitable.
        common_exploitable_suids = ["find", "nmap", "vim", "bash", "cp", "mv"]
        if binary_name in common_exploitable_suids:
            return PrivilegeEscalationVector(
                type="SUID_BINARY",
                details=f"The SUID binary '{binary_path}' can likely be used for privilege escalation.",
                command=f"Check GTFOBins for exploitation details: {gtfobins_url}",
                confidence=0.9
            )
        return None

    async def _analyze_writable_directory(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes a writable directory finding."""
        # For now, this is a placeholder. A real implementation would check if the directory is in the PATH.
        return PrivilegeEscalationVector(
            type="WRITABLE_DIRECTORY",
            details=f"The directory '{finding.description.split(': ')[-1]}' is writable, which could lead to privilege escalation.",
            command="Check if the directory is in the PATH of a privileged user. If so, a malicious binary can be placed there.",
            confidence=0.7
        )

    async def _analyze_unquoted_service_path(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes an unquoted service path finding."""
        return PrivilegeEscalationVector(
            type="UNQUOTED_SERVICE_PATH",
            details=f"The service with path '{finding.description.split(': ')[-1]}' is unquoted and may be vulnerable to privilege escalation.",
            command="Attempt to place a malicious executable in the path to hijack the service.",
            confidence=0.8
        )

    def _analyze_sudo_nopasswd(self, finding: PostExFinding) -> PrivilegeEscalationVector:
        """Analyzes a sudo_nopasswd finding."""
        return PrivilegeEscalationVector(
            type="SUDO_NOPASSWD",
            details="User has NOPASSWD sudo access to all commands, allowing for instant privilege escalation.",
            command="sudo su",
            confidence=1.0
        )

    def _analyze_always_install_elevated(self, finding: PostExFinding) -> PrivilegeEscalationVector:
        """Analyzes an always_install_elevated finding."""
        return PrivilegeEscalationVector(
            type="ALWAYS_INSTALL_ELEVATED",
            details="The AlwaysInstallElevated registry keys are set, allowing any user to install MSI packages with SYSTEM privileges.",
            command="msfvenom -p windows/x64/exec CMD=\"cmd.exe /c whoami\" -f msi -o payload.msi; msiexec /quiet /qn /i payload.msi",
            confidence=1.0
        )
