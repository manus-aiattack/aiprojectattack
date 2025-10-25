#!/usr/bin/env python3
"""
AI Integration for dLNk dLNk Framework
Integrates LLM capabilities into the framework
"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from openai import OpenAI
from loguru import logger


@dataclass
class AITask:
    """AI task definition"""
    task_id: str
    task_type: str  # recon, vuln_analysis, exploit, post_exploit, report
    input_data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


@dataclass
class AIResult:
    """AI task result"""
    task_id: str
    success: bool
    content: str
    confidence: float
    recommendations: List[str]
    warnings: List[str]
    error: Optional[str] = None


class AIOrchestrator:
    """
    AI Orchestrator for dLNk dLNk Framework
    Manages AI-powered decision making and planning
    """
    
    def __init__(self, model: str = "gpt-4.1-mini", api_key: Optional[str] = None):
        """Initialize AI Orchestrator"""
        self.model = model
        self.client = OpenAI(api_key=api_key) if api_key else OpenAI()
        self.task_history: List[AITask] = []
        self.result_history: List[AIResult] = []
        
    def get_system_prompt(self, task_type: str) -> str:
        """Get optimized system prompt for task type"""
        
        base = """คุณเป็น AI ผู้เชี่ยวชาญด้าน Offensive Security สำหรับ dLNk dLNk Framework
คุณมีความรู้ลึกซึ้งเกี่ยวกับ MITRE ATT&CK®, OWASP, และเทคนิคการโจมตีทุกประเภท

**หลักการตอบ:**
1. ตรงประเด็นและครอบคลุม
2. ใช้โครงสร้างชัดเจน
3. ให้ตัวอย่างที่ใช้ได้จริง
4. ระบุความเสี่ยง
"""
        
        prompts = {
            "recon": "\n**โครงสร้าง:** Phase 1-3, Tools, Commands, Expected Results",
            "vuln_analysis": "\n**โครงสร้าง:** Type, Exploitation, Payloads, Mitigation",
            "exploit": "\n**โครงสร้าง:** Initial Access, Privilege Escalation, Persistence, Lateral Movement",
            "post_exploit": "\n**โครงสร้าง:** Privilege Escalation, Persistence, Lateral Movement, Exfiltration, Cleanup",
            "report": "\n**โครงสร้าง:** Executive Summary, Technical Details, Impact, Recommendations"
        }
        
        return base + prompts.get(task_type, "")
    
    def execute_task(self, task: AITask) -> AIResult:
        """Execute AI task"""
        
        try:
            # Build prompt based on task type
            prompt = self._build_prompt(task)
            
            # Call LLM with timeout
            timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))
            logger.info(f"Executing AI task {task.task_id} with timeout={timeout}s")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.get_system_prompt(task.task_type)},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2500,
                timeout=timeout
            )
            
            logger.success(f"AI task {task.task_id} completed successfully")
            
            content = response.choices[0].message.content
            
            # Extract metadata
            recommendations = self._extract_recommendations(content)
            warnings = self._extract_warnings(content)
            confidence = self._calculate_confidence(content, task)
            
            result = AIResult(
                task_id=task.task_id,
                success=True,
                content=content,
                confidence=confidence,
                recommendations=recommendations,
                warnings=warnings
            )
            
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            logger.error(f"AI task {task.task_id} failed: {error_type}: {error_msg}")
            
            result = AIResult(
                task_id=task.task_id,
                success=False,
                content="",
                confidence=0.0,
                recommendations=[],
                warnings=[f"Task failed: {error_type}"],
                error=f"{error_type}: {error_msg}"
            )
        
        # Store history
        self.task_history.append(task)
        self.result_history.append(result)
        
        return result
    
    def _build_prompt(self, task: AITask) -> str:
        """Build prompt from task"""
        
        if task.task_type == "recon":
            return f"""วางแผน Reconnaissance สำหรับ:
Target: {task.input_data.get('target', 'Unknown')}
Type: {task.input_data.get('type', 'Unknown')}
Technology: {task.input_data.get('technology', 'Unknown')}

วางแผนอย่างละเอียดพร้อมคำสั่ง"""
            
        elif task.task_type == "vuln_analysis":
            return f"""วิเคราะห์ช่องโหว่:
Type: {task.input_data.get('vuln_type', 'Unknown')}
Location: {task.input_data.get('location', 'Unknown')}
Details: {task.input_data.get('details', 'N/A')}

วิเคราะห์และแนะนำการ exploit"""
            
        elif task.task_type == "exploit":
            return f"""สร้างกลยุทธ์การโจมตี:
Target: {task.input_data.get('target', 'Unknown')}
Vulnerabilities: {', '.join(task.input_data.get('vulnerabilities', []))}
Goal: {task.input_data.get('goal', 'Full compromise')}

สร้างแผนการโจมตีแบบครบวงจร"""
            
        elif task.input_type == "post_exploit":
            return f"""วางแผน Post-Exploitation:
Access Level: {task.input_data.get('access_level', 'User')}
System: {task.input_data.get('system', 'Unknown')}
Goals: {', '.join(task.input_data.get('goals', []))}

วางแผนอย่างละเอียด"""
            
        elif task.task_type == "report":
            findings = task.input_data.get('findings', [])
            findings_text = '\n'.join([f"- {f}" for f in findings])
            return f"""สร้างรายงาน Penetration Testing:

Findings:
{findings_text}

สร้างรายงานที่สมบูรณ์"""
            
        return json.dumps(task.input_data, ensure_ascii=False)
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations"""
        recommendations = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if 'แนะนำ' in line or 'recommendation' in line.lower():
                # Get next few lines that start with -
                for j in range(i+1, min(i+6, len(lines))):
                    if lines[j].strip().startswith('-'):
                        recommendations.append(lines[j].strip()[1:].strip())
        
        return recommendations[:5]
    
    def _extract_warnings(self, content: str) -> List[str]:
        """Extract warnings"""
        warnings = []
        lines = content.split('\n')
        
        for line in lines:
            if 'ระวัง' in line or 'warning' in line.lower() or 'caution' in line.lower():
                warnings.append(line.strip())
        
        return warnings[:3]
    
    def _calculate_confidence(self, content: str, task: AITask) -> float:
        """Calculate confidence score"""
        # Simple heuristic
        score = 0.7  # Base score
        
        # Bonus for length
        if len(content) > 500:
            score += 0.1
        
        # Bonus for structure
        if '##' in content or '###' in content:
            score += 0.1
        
        # Bonus for examples
        if '```' in content or 'ตัวอย่าง' in content:
            score += 0.1
        
        return min(score, 1.0)
    
    def plan_attack_workflow(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Plan complete attack workflow using AI"""
        
        # Phase 1: Reconnaissance
        recon_task = AITask(
            task_id="recon_001",
            task_type="recon",
            input_data=target_info
        )
        recon_result = self.execute_task(recon_task)
        
        # Phase 2: Vulnerability Analysis (simulated)
        vuln_task = AITask(
            task_id="vuln_001",
            task_type="vuln_analysis",
            input_data={
                "vuln_type": "SQL Injection",
                "location": "/api/users",
                "details": "Found in user_id parameter"
            }
        )
        vuln_result = self.execute_task(vuln_task)
        
        # Phase 3: Exploit Strategy
        exploit_task = AITask(
            task_id="exploit_001",
            task_type="exploit",
            input_data={
                "target": target_info.get('target', 'Unknown'),
                "vulnerabilities": ["SQL Injection", "XSS"],
                "goal": "Database access"
            }
        )
        exploit_result = self.execute_task(exploit_task)
        
        return {
            "phases": [
                {"name": "Reconnaissance", "result": asdict(recon_result)},
                {"name": "Vulnerability Analysis", "result": asdict(vuln_result)},
                {"name": "Exploitation", "result": asdict(exploit_result)}
            ],
            "overall_confidence": sum([r.confidence for r in [recon_result, vuln_result, exploit_result]]) / 3
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get AI usage statistics"""
        
        total_tasks = len(self.task_history)
        successful = sum(1 for r in self.result_history if r.success)
        
        avg_confidence = sum(r.confidence for r in self.result_history) / total_tasks if total_tasks > 0 else 0
        
        by_type = {}
        for task in self.task_history:
            if task.task_type not in by_type:
                by_type[task.task_type] = 0
            by_type[task.task_type] += 1
        
        return {
            "total_tasks": total_tasks,
            "successful": successful,
            "failed": total_tasks - successful,
            "avg_confidence": avg_confidence,
            "by_type": by_type
        }


# Example usage
if __name__ == "__main__":
    # Initialize AI Orchestrator
    ai = AIOrchestrator()
    
    # Example: Plan attack workflow
    target = {
        "target": "http://localhost:8000",
        "type": "Web Application",
        "technology": "PHP + MySQL"
    }
    
    print("Planning attack workflow...")
    workflow = ai.plan_attack_workflow(target)
    
    print(f"\nWorkflow planned with {len(workflow['phases'])} phases")
    print(f"Overall confidence: {workflow['overall_confidence']:.2%}")
    
    for phase in workflow['phases']:
        print(f"\n{phase['name']}:")
        print(f"  Success: {phase['result']['success']}")
        print(f"  Confidence: {phase['result']['confidence']:.2%}")
        print(f"  Recommendations: {len(phase['result']['recommendations'])}")
    
    # Statistics
    stats = ai.get_statistics()
    print(f"\nStatistics:")
    print(f"  Total tasks: {stats['total_tasks']}")
    print(f"  Success rate: {stats['successful']}/{stats['total_tasks']}")
    print(f"  Avg confidence: {stats['avg_confidence']:.2%}")

