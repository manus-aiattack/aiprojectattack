import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, ErrorType, ToolManagerReport
from core.logger import log
import os
import time

class ToolManagerAgent(BaseAgent):
    """
    Manages the dynamic installation and configuration of tools.
    """
    required_tools = [] # This agent manages tools, so it doesn't strictly require external ones for itself

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubsub_manager = self.orchestrator.pubsub_manager
        self.report_class = ToolManagerReport
        self.tool_install_commands = {
            "nmap": "sudo apt-get update && sudo apt-get install -y nmap",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "theharvester": "sudo apt-get install -y theharvester",
            "dirsearch": "pip install dirsearch",
            "whatweb": "sudo apt-get install -y whatweb",
            "feroxbuster": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-linux.sh | sudo bash",
            "sqlmap": "sudo apt-get install -y sqlmap",
            "hydra": "sudo apt-get install -y hydra",
            "wpscan": "sudo apt-get install -y wpscan",
            "commix": "sudo apt-get install -y commix",
            "dalfox": "go install github.com/hahwul/dalfox@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "ffuf": "go install github.com/ffuf/ffuf@latest",
            "gitleaks": "go install github.com/zricethezav/gitleaks@latest",
            "testssl.sh": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh",
            "impacket": "pip install impacket",
            "python-nmap": "pip install python-nmap"
            # Add more tools and their installation commands as needed
        }

    async def run(self, strategy: Strategy) -> ToolManagerReport:
        start_time = time.time()
        directive = strategy.directive
        
        if "install tool" in directive:
            tool_name = strategy.context.get("tool_name")
            if tool_name:
                return await self.install_tool(tool_name, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name not specified for installation."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool installation failed: Tool name missing.",
                    action="install tool"
                )
        elif "configure tool" in directive:
            tool_name = strategy.context.get("tool_name")
            config_data = strategy.context.get("config_data")
            if tool_name and config_data:
                return await self.configure_tool(tool_name, config_data, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name or config data not specified for configuration."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool configuration failed: Missing tool name or config data.",
                    action="configure tool"
                )
        elif "verify tool" in directive:
            tool_name = strategy.context.get("tool_name")
            if tool_name:
                return await self.verify_tool(tool_name, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name not specified for verification."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool verification failed: Tool name missing.",
                    action="verify tool"
                )
        else:
            end_time = time.time()
            return self.create_report(
                errors=[f"Unknown directive for ToolManagerAgent: {directive}"],
                error_type=ErrorType.LOGIC,
                summary=f"Unknown directive for ToolManagerAgent: {directive}",
                action="unknown"
            )

    async def install_tool(self, tool_name: str, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Attempting to install tool: {tool_name}")
        install_command = self.tool_install_commands.get(tool_name)

        if not install_command:
            end_time = time.time()
            return self.create_report(
                errors=[f"Installation command for tool '{tool_name}' not found."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Tool installation failed: No installation command for '{tool_name}'.",
                tool_name=tool_name,
                action="install tool"
            )

        try:
            log.info(f"ToolManagerAgent: Executing installation command: {install_command}")
            result = await self.orchestrator.run_shell_command(install_command)

            if result["exit_code"] == 0:
                log.success(f"ToolManagerAgent: Successfully installed tool: {tool_name}")
                await self.pubsub_manager.publish(
                    "tool_events",
                    {
                        "event_type": "TOOL_INSTALLED",
                        "tool_name": tool_name,
                        "timestamp": time.time()
                    }
                )
                end_time = time.time()
                return self.create_report(
                    summary=f"Tool '{tool_name}' installed successfully.",
                    tool_name=tool_name,
                    action="install tool",
                    output=result.get("stdout")
                )
            else:
                error_message = result["stderr"] or f"Installation failed with exit code {result['exit_code']}"
                log.error(f"ToolManagerAgent: Failed to install tool '{tool_name}': {error_message}")
                end_time = time.time()
                return self.create_report(
                    errors=[f"Failed to install tool '{tool_name}': {error_message}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"Tool installation failed for '{tool_name}'.",
                    tool_name=tool_name,
                    action="install tool",
                    output=result.get("stdout") + result.get("stderr")
                )

        except Exception as e:
            log.error(f"ToolManagerAgent: An unexpected error occurred during installation of '{tool_name}': {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred during installation: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Tool installation failed due to unexpected error: {e}",
                tool_name=tool_name,
                action="install tool"
            )

    async def configure_tool(self, tool_name: str, config_data: dict, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Attempting to configure tool: {tool_name}")
        # This is a placeholder. Actual configuration would depend on the tool.
        # For example, writing to a config file, setting environment variables, etc.
        summary = f"Configuration for '{tool_name}' with data '{config_data}' is not yet implemented."
        log.warning(f"ToolManagerAgent: {summary}")
        end_time = time.time()
        return self.create_report(
            errors=[summary],
            error_type=ErrorType.NOT_IMPLEMENTED,
            summary=summary,
            tool_name=tool_name,
            action="configure tool"
        )

    async def verify_tool(self, tool_name: str, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Verifying installation of tool: {tool_name}")
        # This is a placeholder. Actual verification would depend on the tool.
        # For example, running `tool_name --version` or checking for its executable.
        check_command = f"which {tool_name}" # Basic check for executables
        if tool_name == "testssl.sh":
            check_command = "testssl.sh --version" # Specific check
        elif tool_name == "impacket":
            check_command = "python3 -c 'import impacket'"
        elif tool_name == "python-nmap":
            check_command = "python3 -c 'import nmap'"

        try:
            result = await self.orchestrator.run_shell_command(check_command)
            if result["exit_code"] == 0:
                summary = f"Tool '{tool_name}' verified successfully."
                log.success(f"ToolManagerAgent: {summary}")
                end_time = time.time()
                return self.create_report(
                    summary=summary,
                    tool_name=tool_name,
                    action="verify tool",
                    output=result.get("stdout")
                )
            else:
                error_message = result["stderr"] or f"Verification failed with exit code {result['exit_code']}"
                log.warning(f"ToolManagerAgent: Tool '{tool_name}' verification failed: {error_message}")
                end_time = time.time()
                return self.create_report(
                    errors=[f"Tool '{tool_name}' verification failed: {error_message}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"Tool '{tool_name}' verification failed.",
                    tool_name=tool_name,
                    action="verify tool",
                    output=result.get("stdout") + result.get("stderr")
                )
        except Exception as e:
            log.error(f"ToolManagerAgent: An unexpected error occurred during verification of '{tool_name}': {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred during verification: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Tool verification failed due to unexpected error: {e}",
                tool_name=tool_name,
                action="verify tool"
            )
