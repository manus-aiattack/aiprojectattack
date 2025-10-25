from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import yaml
import os

class WorkflowManagerAgent(BaseAgent):
    """
    An agent that can dynamically modify the workflow.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This is a potential issue, workspace_dir is not on the orchestrator.
        # I will assume it is passed in the constructor or available in settings.
        from config import settings
        self.workflow_path = os.path.join(settings.WORKSPACE_DIR, 'workflows', 'default_workflow.yaml')

    async def run(self, strategy: Strategy) -> AgentData:
        """
        Dynamically modifies the workflow based on the directive.
        """
        directive = strategy.directive
        
        if "insert phase" in directive:
            return await self.insert_phase(strategy.context)
        elif "remove phase" in directive:
            return await self.remove_phase(strategy.context)
        else:
            return AgentData(success=False, errors=[f"Unknown directive for WorkflowManagerAgent: {directive}"])

    async def insert_phase(self, context: dict) -> AgentData:
        """
        Inserts a new phase into the workflow.
        """
        phase_to_insert = context.get("phase_to_insert")
        after_phase = context.get("after_phase")

        if not phase_to_insert or not after_phase:
            return AgentData(success=False, errors=["Missing 'phase_to_insert' or 'after_phase' in context."])

        try:
            with open(self.workflow_path, 'r') as f:
                workflow = yaml.safe_load(f)

            if 'phases' not in workflow:
                workflow['phases'] = []

            # Find the index of the phase to insert after
            insert_index = -1
            for i, phase in enumerate(workflow['phases']):
                if phase['name'] == after_phase:
                    insert_index = i + 1
                    break
            
            if insert_index == -1:
                return AgentData(success=False, errors=[f"Phase '{after_phase}' not found in workflow."])

            workflow['phases'].insert(insert_index, phase_to_insert)

            with open(self.workflow_path, 'w') as f:
                yaml.dump(workflow, f)

            return AgentData(success=True, summary=f"Inserted phase '{phase_to_insert.get('name')}' after '{after_phase}'.")

        except Exception as e:
            return AgentData(success=False, errors=[f"Failed to insert phase: {e}"])

    async def remove_phase(self, context: dict) -> AgentData:
        """
        Removes a phase from the workflow.
        """
        phase_to_remove = context.get("phase_to_remove")

        if not phase_to_remove:
            return AgentData(success=False, errors=["Missing 'phase_to_remove' in context."])

        try:
            with open(self.workflow_path, 'r') as f:
                workflow = yaml.safe_load(f)

            if 'phases' not in workflow:
                return AgentData(success=False, errors=["Workflow has no phases."])

            original_length = len(workflow['phases'])
            workflow['phases'] = [p for p in workflow['phases'] if p['name'] != phase_to_remove]
            
            if len(workflow['phases']) == original_length:
                return AgentData(success=False, errors=[f"Phase '{phase_to_remove}' not found in workflow."])

            with open(self.workflow_path, 'w') as f:
                yaml.dump(workflow, f)

            return AgentData(success=True, summary=f"Removed phase '{phase_to_remove}'.")

        except Exception as e:
            return AgentData(success=False, errors=[f"Failed to remove phase: {e}"])
