"""
Main Orchestrator for dLNk dLNk Framework
Coordinates the execution of agents and manages the attack workflow
"""

import asyncio
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from pathlib import Path
from datetime import datetime

from .logger import log
from .agent_registry import AgentRegistry
from .context_manager import ContextManager
from .pubsub_manager import PubSubManager
from .data_models import Strategy, AgentData, ErrorType, AttackPhase
from .workflow_executor import WorkflowExecutor
from .data_exfiltration import DataExfiltrator
from .auto_exploit import AutoExploiter


class Orchestrator:
    """Main orchestrator that manages agent execution and workflow"""

    def __init__(self, config_path: Optional[str] = None, workspace_dir: Optional[str] = None):
        """
        Initialize the Orchestrator
        
        Args:
            config_path: Path to configuration file
            workspace_dir: Working directory for the framework
        """
        self.config_path = config_path
        self.workspace_dir = workspace_dir or Path.cwd() / "workspace"
        self.workspace_dir = Path(self.workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Initialize core components
        self.agent_registry = AgentRegistry()
        self.context_manager = ContextManager()
        self.pubsub_manager = PubSubManager()
        self.workflow_executor = WorkflowExecutor(self)
        self.data_exfiltrator = DataExfiltrator(workspace_dir=str(self.workspace_dir))
        self.auto_exploiter = AutoExploiter(orchestrator=self)
        
        # State management
        self.running = False
        self.campaign_results = []
        self.current_phase = None
        self.start_time = None
        self.end_time = None
        
        # Safety: Blocked domains
        self.blocked_domains = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1'
        ]

        log.info("Orchestrator initialized successfully")

    async def initialize(self):
        """Initialize and discover all agents"""
        log.info("Initializing Orchestrator...")
        
        try:
            # Auto-discover agents
            self.agent_registry.auto_discover_agents(agents_dir=str(Path(__file__).parent.parent / "agents"))
            log.success(f"Discovered {len(self.agent_registry.agents)} agents")
            
            # Initialize context manager
            await self.context_manager.setup()
            log.success("Context manager initialized")
            
            # Initialize PubSub manager
            await self.pubsub_manager.setup()
            log.success("PubSub manager initialized")

            # Re-initialize logger with Redis client for streaming
            # Dynamically reconfigure the existing logger with Redis client
            from core.logger import get_logger, log as current_log_instance
            new_log_instance = get_logger(redis_client=self.context_manager.redis)
            # Copy handlers from new_log_instance to current_log_instance
            current_log_instance.handlers = new_log_instance.handlers
            current_log_instance.setLevel(new_log_instance.level)
            current_log_instance.propagate = new_log_instance.propagate
            
        except Exception as e:
            log.error(f"Failed to initialize Orchestrator: {e}", exc_info=True)
            raise

    async def load_workflow(self, workflow_path: str) -> Dict[str, Any]:
        """Load workflow configuration from YAML file"""
        try:
            with open(workflow_path, 'r') as f:
                workflow = yaml.safe_load(f)
            log.info(f"Loaded workflow: {workflow.get('workflow_name', 'Unknown')}")
            return workflow
        except Exception as e:
            log.error(f"Failed to load workflow: {e}")
            raise

    async def execute_workflow(self, workflow_path: str, target: Dict[str, Any]) -> List[AgentData]:
        """
        Execute a complete workflow against a target
        
        Args:
            workflow_path: Path to the workflow YAML file
            target: Target information dictionary
            
        Returns:
            List of AgentData results from all executed agents
        """
        self.running = True
        self.start_time = datetime.now()
        self.campaign_results = []
        try:
            # Load workflow
            workflow = await self.load_workflow(workflow_path)
            
            # Generate a unique workflow ID for this execution
            workflow_run_id = f"workflow_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            await self.context_manager.set_context("current_workflow_id", workflow_run_id)
            await self.context_manager.set_context("current_target", target)
            
            # Execute phases
            phases = workflow.get('phases', [])
            for phase in phases:
                result = await self._execute_phase(phase)
                
                # Check phase result and determine next phase
                if not result:
                    log.warning(f"Phase {phase.get('name')} failed, checking for failure handler")
                    next_phase = phase.get('on_failure')
                else:
                    next_phase = phase.get('on_success')
                
                if next_phase:
                    log.info(f"Transitioning to phase: {next_phase}")

            log.success("Workflow execution completed")
            
        except Exception as e:
            log.error(f"Workflow execution failed: {e}", exc_info=True)
            raise
        finally:
            self.running = False
            self.end_time = datetime.now()

        return self.campaign_results

    async def _execute_phase(self, phase: Dict[str, Any]) -> bool:
        """Execute a single phase with its agents"""
        phase_name = phase.get('name', 'Unknown')
        self.current_phase = phase_name
        
        log.phase(f"Executing phase: {phase_name}")
        
        try:
            # Check for parallel agents
            if 'parallel_agents' in phase:
                results = await self._execute_parallel_agents(phase['parallel_agents'])
            else:
                results = await self._execute_sequential_agents(phase.get('agents', []))
            
            # Store results
            self.campaign_results.extend(results)
            
            # Check if all agents succeeded
            success = all(r.success for r in results if r)
            
            if success:
                log.success(f"Phase {phase_name} completed successfully")
            else:
                log.warning(f"Phase {phase_name} had some failures")
            
            return success
            
        except Exception as e:
            log.error(f"Phase {phase_name} execution failed: {e}", exc_info=True)
            return False

    async def _execute_sequential_agents(self, agents: List[Dict[str, Any]]) -> List[AgentData]:
        """Execute agents sequentially"""
        results = []
        
        for agent_config in agents:
            result = await self._execute_agent_config(agent_config)
            results.append(result)
            
            # Stop if an agent fails (optional - can be configured)
            if result and not result.success:
                log.warning(f"Agent {agent_config.get('name')} failed, continuing with next agent")
        
        return results

    async def _execute_parallel_agents(self, agents: List[Dict[str, Any]]) -> List[AgentData]:
        """Execute agents in parallel"""
        tasks = [self._execute_agent_config(agent_config) for agent_config in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        # Filter out None results from failed agents, but keep successful ones
        return [result for result in results if not isinstance(result, Exception) and result is not None]

    async def _execute_agent_config(self, agent_config: Dict[str, Any]) -> Optional[AgentData]:
        """Execute a single agent based on configuration"""
        agent_name = agent_config.get('name')
        directive = agent_config.get('directive', '')
        context = agent_config.get('context', {})
        
        try:
            workflow_id = await self.context_manager.get_context('current_workflow_id')
            target_info = await self.context_manager.get_context('current_target')
            target_id = target_info.get('name') if target_info else None

            log.info(f"Executing agent: {agent_name}", extra={
                "agent_name": agent_name,
                "workflow_id": workflow_id,
                "target_id": target_id
            })
            
            # Get agent instance
            agent = await self.agent_registry.get_agent(
                agent_name,
                context_manager=self.context_manager,
                orchestrator=self
            )
            
            # Create strategy
            strategy = Strategy(
               phase=AttackPhase[self.current_phase.upper()],
                directive=directive,
                context=context,
                next_agent=agent_name # Add required next_agent field
            )
            
            # Execute agent with error handling
            result = await agent.execute_with_error_handling(strategy)
            
            if result.success:
                log.success(f"Agent {agent_name} completed successfully")
            else:
                log.warning(f"Agent {agent_name} failed: {result.errors}")
            
            return result
            
        except Exception as e:
            log.error(f"Failed to execute agent {agent_name}: {e}", exc_info=True)
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[str(e)],
                error_type=ErrorType.EXECUTION_FAILED
            )

    def is_target_safe(self, target: str) -> bool:
        """
        ตรวจสอบว่า target ปลอดภัยหรือไม่ (ไม่ใช่ localhost หรือ internal)
        
        Args:
            target: URL หรือ IP ของเป้าหมาย
        
        Returns:
            True ถ้าปลอดภัย, False ถ้าเป็น blocked domain
        """
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(target if '://' in target else f'http://{target}')
            hostname = parsed.hostname or parsed.netloc
            
            # Check blocked domains
            for blocked in self.blocked_domains:
                if blocked in hostname.lower():
                    log.error(f"[SAFETY] Target {target} is BLOCKED (matches {blocked})")
                    return False
            
            # Check private IP ranges
            if hostname.startswith('192.168.') or hostname.startswith('10.') or hostname.startswith('172.'):
                log.warning(f"[SAFETY] Target {target} is in private IP range")
                # Allow private IPs but log warning
                return True
            
            return True
            
        except Exception as e:
            log.error(f"[SAFETY] Failed to parse target {target}: {e}")
            return False
    
    async def auto_exploit_target(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        โจมตีเป้าหมายอัตโนมัติ
        
        Args:
            target: URL หรือ IP ของเป้าหมาย
            context: ข้อมูลเพิ่มเติม
        
        Returns:
            ผลการโจมตีและ loot ที่ได้
        """
        # Safety check
        if not self.is_target_safe(target):
            return {
                "success": False,
                "error": "Target is blocked for safety reasons",
                "target": target
            }
        
        log.info(f"[Orchestrator] Starting auto exploitation on {target}")
        
        # Use AutoExploiter
        result = await self.auto_exploiter.auto_exploit_target(target, context)
        
        return result

    async def execute_agent_directly(self, agent_name: str, strategy: Strategy) -> AgentData:
        """Execute a single agent directly"""
        # Safety check on target
        target = strategy.context.get('url') or strategy.context.get('target')
        if target and not self.is_target_safe(target):
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[f"Target {target} is blocked for safety reasons"],
                error_type=ErrorType.EXECUTION_FAILED
            )
        
        try:
            agent = await self.agent_registry.get_agent(
                agent_name,
                context_manager=self.context_manager,
                orchestrator=self
            )
            workflow_id = await self.context_manager.get_context("current_workflow_id")
            target_info = await self.context_manager.get_context("current_target")
            target_id = target_info.get("name") if target_info else None
            
            # Pass extra context to the agent's logger
            strategy.context["workflow_id"] = workflow_id
            strategy.context["target_id"] = target_id

            return await agent.execute_with_error_handling(strategy, extra={
                "workflow_id": workflow_id,
                "target_id": target_id,
                "agent_name": agent_name # Ensure agent_name is also explicitly passed
            })
        except Exception as e:
            log.error(f"Failed to execute agent {agent_name}: {e}", exc_info=True)
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[str(e)],
                error_type=ErrorType.EXECUTION_FAILED
            )

    def get_registered_agents(self) -> List[str]:
        """Get list of all registered agents"""
        return list(self.agent_registry.agents.keys())

    def get_agent_info(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific agent"""
        agent_class = self.agent_registry.get_agent_class(agent_name)
        if not agent_class:
            return None
        
        return {
            'name': agent_name,
            'class': agent_class.__name__,
            'doc': agent_class.__doc__,
            'config': self.agent_registry.agent_configs.get(agent_name, {})
        }

    async def cleanup(self):
        """Cleanup resources"""
        log.info("Cleaning up Orchestrator resources...")
        await self.context_manager.cleanup()
        await self.pubsub_manager.close()
        log.success("Cleanup completed")

    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status"""
        return {
            'running': self.running,
            'current_phase': self.current_phase,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'results_count': len(self.campaign_results),
            'agents_registered': len(self.agent_registry.agents)
        }

