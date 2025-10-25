
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log

from core.base_agent import BaseAgent


class IntelligentCredentialAttackAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["hydra"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)

    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        log.info("Running Intelligent Credential Attack Agent...")

        credential_harvester_agent = self.orchestrator.agents["CredentialHarvesterAgent"]
        hydra_agent = self.orchestrator.agents["HydraAgent"]

        # Step 1: Harvest credentials
        log.info("Step 1: Harvesting credentials...")
        harvest_report = await credential_harvester_agent.run(strategy)
        if not harvest_report.success:
            return self.create_report(success=False, errors=["Credential harvesting failed."])

        # Step 2: Run Hydra with the harvested credentials
        log.info("Step 2: Running Hydra with harvested credentials...")
        hydra_report = await hydra_agent.run(strategy)

        log.info("Intelligent Credential Attack Agent finished.")
        return self.create_report(success=hydra_report.success, findings=hydra_report.findings)
