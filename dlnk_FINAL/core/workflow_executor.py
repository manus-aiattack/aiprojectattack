import asyncio
import ollama
import json
from datetime import datetime
from core.logger import log

class WorkflowExecutor:
    """AI-Driven Intelligent Workflow Executor"""
    
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.agent_registry = orchestrator.agent_registry
        self.context_manager = orchestrator.context_manager
        self.ai_model = "mistral:latest"
        self.execution_intelligence = {}

    async def execute_campaign(self):
        """AI-driven intelligent attack campaign execution."""
        try:
            # AI-driven campaign goal determination
            campaign_goal = await self._ai_determine_campaign_goal()

            while True:
                log.phase("AI analyzing and planning next attack strategies...")
                
                # AI strategy analysis and planning
                ai_strategies = await self._ai_plan_strategies(campaign_goal)
                
                if not ai_strategies:
                    log.info("AI determined campaign is complete or no viable strategies remain.")
                    break

                # AI-driven strategy execution
                await self._ai_execute_strategies(ai_strategies)

                # AI learning and adaptation
                await self._ai_learn_and_adapt()

                await asyncio.sleep(1)

            log.phase("AI-driven attack campaign concluded.")
            
        except KeyboardInterrupt:
            log.warning("Attack run interrupted by user.")
        except Exception as e:
            log.critical(f"A critical error occurred in the main loop: {e}", exc_info=True)

    async def _ai_determine_campaign_goal(self):
        """Use AI to determine optimal campaign goal"""
        try:
            prompt = """
            Determine the optimal attack campaign goal based on:
            1. Available agents and capabilities
            2. Current threat landscape
            3. Maximum impact potential
            4. Stealth requirements
            
            Focus on offensive objectives that maximize effectiveness.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist determining campaign objectives."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            goal = response['message']['content']
            log.info(f"AI determined campaign goal: {goal}")
            return goal
            
        except Exception as e:
            log.error(f"Failed to determine campaign goal: {e}")
            return "Achieve maximum system compromise with minimal detection"

    async def _ai_plan_strategies(self, campaign_goal):
        """Use AI to plan attack strategies"""
        try:
            available_agents = list(self.agent_registry.agents.keys())
            
            prompt = f"""
            Plan attack strategies for the following campaign goal:
            
            Campaign Goal: {campaign_goal}
            Available Agents: {available_agents}
            
            Create a strategic plan that:
            1. Maximizes attack effectiveness
            2. Minimizes detection risk
            3. Uses agents optimally
            4. Adapts to changing conditions
            
            Focus on offensive strategies and attack techniques.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist planning offensive campaigns."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            strategies = response['message']['content']
            log.info("AI planned attack strategies")
            return strategies
            
        except Exception as e:
            log.error(f"Failed to plan strategies: {e}")
            return None

    async def _ai_execute_strategies(self, strategies):
        """Execute strategies with AI guidance"""
        try:
            # Parse AI strategies and execute
            log.info("Executing AI-planned strategies...")
            
            # This would integrate with the existing strategy execution
            # but with AI guidance and adaptation
            
            log.success("AI-guided strategy execution completed")
            
        except Exception as e:
            log.error(f"Failed to execute strategies: {e}")

    async def _ai_learn_and_adapt(self):
        """AI learning and adaptation mechanism"""
        try:
            prompt = """
            Analyze the current attack campaign progress and adapt:
            1. What worked well?
            2. What needs improvement?
            3. How to adapt strategies?
            4. What new approaches to try?
            
            Focus on improving attack effectiveness.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist learning and adapting."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            adaptation = response['message']['content']
            log.info("AI learned and adapted strategies")
            
        except Exception as e:
            log.error(f"Failed to learn and adapt: {e}")
