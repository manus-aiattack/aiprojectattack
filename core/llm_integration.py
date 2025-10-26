"""
dLNk Attack Platform - LLM Integration
Integrates with OpenAI/Gemini for AI-powered decision making
"""

import os
import json
from typing import Dict, List, Optional, Any
from loguru import logger

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("[LLM] OpenAI library not available")


class LLMIntegration:
    """LLM Integration for AI Decision Making"""
    
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "openai")
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")
        self.fallback_model = os.getenv("LLM_FALLBACK_MODEL", "gpt-4.1-nano")
        self.temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.7"))
        self.max_tokens = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
        self.auto_decision = os.getenv("AI_AUTO_DECISION", "true").lower() == "true"
        self.confidence_threshold = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.75"))
        
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize LLM client"""
        if not OPENAI_AVAILABLE:
            logger.error("[LLM] OpenAI library not installed. Run: pip3 install openai")
            return
        
        try:
            # OpenAI API Key is pre-configured in environment
            self.client = OpenAI()
            logger.success(f"[LLM] Client initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"[LLM] Failed to initialize client: {e}")
    
    def is_available(self) -> bool:
        """Check if LLM is available"""
        return self.client is not None
    
    def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = False
    ) -> Optional[str]:
        """Generate completion from LLM"""
        if not self.is_available():
            logger.warning("[LLM] Client not available")
            return None
        
        try:
            messages = []
            
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            
            messages.append({"role": "user", "content": prompt})
            
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature or self.temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }
            
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            
            response = self.client.chat.completions.create(**kwargs)
            
            result = response.choices[0].message.content
            logger.debug(f"[LLM] Generated completion: {result[:100]}...")
            
            return result
            
        except Exception as e:
            logger.error(f"[LLM] Completion error: {e}")
            
            # Try fallback model
            if self.fallback_model and self.fallback_model != self.model:
                try:
                    logger.info(f"[LLM] Trying fallback model: {self.fallback_model}")
                    kwargs["model"] = self.fallback_model
                    response = self.client.chat.completions.create(**kwargs)
                    result = response.choices[0].message.content
                    return result
                except Exception as e2:
                    logger.error(f"[LLM] Fallback model error: {e2}")
            
            return None
    
    def analyze_vulnerability(self, vuln_data: Dict) -> Optional[Dict]:
        """Analyze vulnerability and suggest exploitation strategy"""
        system_prompt = """You are an expert penetration tester and vulnerability analyst.
Analyze the given vulnerability data and provide exploitation recommendations.
Return your analysis in JSON format with these fields:
- severity: critical/high/medium/low
- exploitability: easy/medium/hard
- recommended_exploit: name of recommended exploit
- attack_vector: how to exploit
- prerequisites: what's needed
- success_probability: 0.0-1.0
- stealth_level: high/medium/low
- detection_risk: high/medium/low
"""
        
        prompt = f"""Analyze this vulnerability:

Vulnerability Data:
{json.dumps(vuln_data, indent=2)}

Provide detailed exploitation analysis and recommendations."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                return json.loads(result)
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None
    
    def suggest_attack_strategy(self, target_info: Dict) -> Optional[Dict]:
        """Suggest attack strategy based on target information"""
        system_prompt = """You are an expert penetration tester specializing in attack planning.
Analyze the target information and suggest the best attack strategy.
Return your strategy in JSON format with these fields:
- attack_phases: list of phases (reconnaissance, scanning, exploitation, post-exploitation)
- recommended_tools: list of tools to use
- attack_vectors: list of potential attack vectors
- priority_targets: list of high-value targets
- estimated_time: estimated time in hours
- success_probability: 0.0-1.0
- stealth_recommendations: how to stay stealthy
"""
        
        prompt = f"""Plan an attack strategy for this target:

Target Information:
{json.dumps(target_info, indent=2)}

Provide a comprehensive attack strategy."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                return json.loads(result)
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None
    
    def optimize_payload(self, payload: str, target_info: Dict) -> Optional[str]:
        """Optimize payload for specific target"""
        system_prompt = """You are an expert in payload development and evasion techniques.
Optimize the given payload for the specific target while maintaining functionality.
Consider:
- Target OS and architecture
- Security controls (AV, EDR, WAF)
- Evasion techniques
- Obfuscation methods
Return only the optimized payload code."""
        
        prompt = f"""Optimize this payload for the target:

Original Payload:
{payload}

Target Information:
{json.dumps(target_info, indent=2)}

Provide the optimized payload."""
        
        result = self.generate_completion(prompt, system_prompt)
        return result
    
    def analyze_scan_results(self, scan_results: Dict) -> Optional[Dict]:
        """Analyze scan results and identify vulnerabilities"""
        system_prompt = """You are an expert vulnerability analyst.
Analyze the scan results and identify potential vulnerabilities and attack vectors.
Return your analysis in JSON format with these fields:
- vulnerabilities_found: list of vulnerabilities
- attack_surface: description of attack surface
- recommended_next_steps: list of next steps
- high_value_targets: list of high-value targets
- security_posture: weak/moderate/strong
"""
        
        prompt = f"""Analyze these scan results:

Scan Results:
{json.dumps(scan_results, indent=2)}

Identify vulnerabilities and attack opportunities."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                return json.loads(result)
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None
    
    def generate_exploit_code(self, vuln_description: str, target_info: Dict) -> Optional[str]:
        """Generate exploit code for vulnerability"""
        system_prompt = """You are an expert exploit developer.
Generate working exploit code for the described vulnerability.
The code should be production-ready and include error handling.
Use Python unless otherwise specified."""
        
        prompt = f"""Generate exploit code for this vulnerability:

Vulnerability:
{vuln_description}

Target Information:
{json.dumps(target_info, indent=2)}

Provide complete, working exploit code."""
        
        result = self.generate_completion(prompt, system_prompt, max_tokens=4000)
        return result
    
    def suggest_privilege_escalation(self, system_info: Dict) -> Optional[Dict]:
        """Suggest privilege escalation techniques"""
        system_prompt = """You are an expert in privilege escalation techniques.
Analyze the system information and suggest privilege escalation methods.
Return your suggestions in JSON format with these fields:
- techniques: list of applicable techniques
- recommended_order: ordered list of techniques to try
- success_probability: 0.0-1.0 for each technique
- required_tools: tools needed
- detection_risk: high/medium/low for each technique
"""
        
        prompt = f"""Suggest privilege escalation techniques for this system:

System Information:
{json.dumps(system_info, indent=2)}

Provide detailed privilege escalation recommendations."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                return json.loads(result)
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None
    
    def analyze_defense_evasion(self, security_controls: List[str]) -> Optional[Dict]:
        """Analyze security controls and suggest evasion techniques"""
        system_prompt = """You are an expert in defense evasion and anti-forensics.
Analyze the security controls and suggest evasion techniques.
Return your analysis in JSON format with these fields:
- detected_controls: list of detected security controls
- evasion_techniques: list of applicable evasion techniques
- obfuscation_methods: list of obfuscation methods
- recommended_approach: overall recommended approach
- success_probability: 0.0-1.0
"""
        
        prompt = f"""Analyze these security controls and suggest evasion:

Security Controls:
{json.dumps(security_controls, indent=2)}

Provide evasion recommendations."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                return json.loads(result)
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None
    
    def make_decision(self, context: str, options: List[str]) -> Optional[Dict]:
        """Make AI decision based on context and options"""
        if not self.auto_decision:
            logger.info("[LLM] Auto-decision disabled")
            return None
        
        system_prompt = """You are an AI decision-making system for a penetration testing platform.
Analyze the context and choose the best option.
Return your decision in JSON format with these fields:
- chosen_option: the selected option
- reasoning: explanation of why this option was chosen
- confidence: 0.0-1.0 confidence score
- alternative_options: list of alternative options in order of preference
"""
        
        prompt = f"""Make a decision based on this context:

Context:
{context}

Available Options:
{json.dumps(options, indent=2)}

Choose the best option and explain your reasoning."""
        
        result = self.generate_completion(prompt, system_prompt, json_mode=True)
        
        if result:
            try:
                decision = json.loads(result)
                
                # Check confidence threshold
                if decision.get("confidence", 0) < self.confidence_threshold:
                    logger.warning(f"[LLM] Decision confidence {decision.get('confidence')} below threshold {self.confidence_threshold}")
                    return None
                
                return decision
            except:
                logger.error("[LLM] Failed to parse JSON response")
        
        return None


# Global instance
llm_integration = LLMIntegration()


def get_llm_integration() -> LLMIntegration:
    """Get LLM integration instance"""
    return llm_integration

