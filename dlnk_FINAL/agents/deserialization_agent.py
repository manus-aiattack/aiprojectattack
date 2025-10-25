"""
DeserializationAgent - Alias for DeserializationExploiterAgent
This provides compatibility with workflows that reference 'DeserializationAgent'
"""

from agents.deserialization_exploiter_agent import DeserializationExploiterAgent


class DeserializationAgent(DeserializationExploiterAgent):
    """
    Alias class for DeserializationExploiterAgent
    Provides backward compatibility with workflows using 'DeserializationAgent' name
    """
    pass
