import asyncio
from typing import Dict, List, Any, Optional
from core.logger import log
from core.result_aggregator import ResultAggregator
from datetime import datetime
import json
import os


class ReportGenerator:
    """สร้างรายงานแบบครอบคลุม"""

    def __init__(self, result_aggregator: ResultAggregator):
        self.result_aggregator = result_aggregator
        self.report_templates = {}
        self.generated_reports = {}

    async def initialize(self):
        """เริ่มต้น Report Generator"""
        try:
            # โหลด report templates
            await self._load_report_templates()

            log.info("✅ Report Generator เริ่มต้นสำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ Report Generator เริ่มต้นล้มเหลว: {e}")
            return False

    async def _load_report_templates(self):
        """โหลด report templates"""
        try:
            self.report_templates = {
                "executive_summary": self._generate_executive_summary,
                "technical_details": self._generate_technical_details,
                "vulnerability_report": self._generate_vulnerability_report,
                "exploit_report": self._generate_exploit_report,
                "findings_report": self._generate_findings_report,
                "recommendations": self._generate_recommendations,
                "full_report": self._generate_full_report
            }

        except Exception as e:
            log.error(f"❌ โหลด report templates ล้มเหลว: {e}")

    async def generate_report(self, session_id: str, results: Dict[str, Any] = None,
                              report_type: str = "full_report", output_format: str = "json") -> Dict[str, Any]:
        """สร้างรายงาน"""
        try:
            log.info(f"📝 สร้างรายงานสำหรับ session: {session_id}")

            # รับข้อมูลที่รวมแล้ว
            if results is None:
                results = self.result_aggregator.get_aggregated_data(
                    session_id)

            if not results:
                return {"error": f"ไม่พบข้อมูลสำหรับ session {session_id}"}

            # สร้างรายงานตามประเภท
            if report_type not in self.report_templates:
                return {"error": f"ประเภทรายงาน '{report_type}' ไม่พบ"}

            report_data = await self.report_templates[report_type](results)

            # บันทึกรายงาน
            report_id = f"{session_id}_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.generated_reports[report_id] = {
                "session_id": session_id,
                "report_type": report_type,
                "output_format": output_format,
                "timestamp": datetime.now().isoformat(),
                "data": report_data
            }

            # บันทึกลงไฟล์
            if output_format == "json":
                await self._save_json_report(report_id, report_data)
            elif output_format == "html":
                await self._save_html_report(report_id, report_data)
            elif output_format == "pdf":
                await self._save_pdf_report(report_id, report_data)

            log.success(f"✅ สร้างรายงาน {report_type} เสร็จสิ้น")
            return {
                "success": True,
                "report_id": report_id,
                "report_type": report_type,
                "output_format": output_format,
                "data": report_data
            }

        except Exception as e:
            log.error(f"❌ สร้างรายงานล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างสรุปผู้บริหาร"""
        try:
            summary = {
                "title": "Executive Summary",
                "timestamp": datetime.now().isoformat(),
                "overview": {
                    "total_phases": results.get("statistics", {}).get("total_phases", 0),
                    "total_agents": results.get("statistics", {}).get("total_agents", 0),
                    "total_vulnerabilities": results.get("statistics", {}).get("total_vulnerabilities", 0),
                    "total_exploits": results.get("statistics", {}).get("total_exploits", 0),
                    "total_findings": results.get("statistics", {}).get("total_findings", 0)
                },
                "key_findings": [],
                "risk_assessment": {
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0
                },
                "recommendations": []
            }

            # วิเคราะห์ key findings
            vulnerabilities = results.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low").lower()
                if severity == "high":
                    summary["risk_assessment"]["high_risk"] += 1
                elif severity == "medium":
                    summary["risk_assessment"]["medium_risk"] += 1
                else:
                    summary["risk_assessment"]["low_risk"] += 1

                if severity in ["high", "critical"]:
                    summary["key_findings"].append({
                        "type": "vulnerability",
                        "severity": severity,
                        "description": vuln.get("description", ""),
                        "location": vuln.get("location", "")
                    })

            # วิเคราะห์ exploits
            exploits = results.get("exploits", [])
            for exploit in exploits:
                if exploit.get("success", False):
                    summary["key_findings"].append({
                        "type": "exploit",
                        "success": True,
                        "description": exploit.get("description", ""),
                        "target": exploit.get("target", "")
                    })

            # วิเคราะห์ findings
            findings = results.get("findings", [])
            for finding in findings:
                if "sensitive" in finding.get("description", "").lower():
                    summary["key_findings"].append({
                        "type": "finding",
                        "sensitive": True,
                        "description": finding.get("description", ""),
                        "location": finding.get("location", "")
                    })

            # สร้างคำแนะนำ
            if summary["risk_assessment"]["high_risk"] > 0:
                summary["recommendations"].append(
                    "พบช่องโหว่ระดับสูง ควรแก้ไขทันที")

            if summary["risk_assessment"]["medium_risk"] > 0:
                summary["recommendations"].append(
                    "พบช่องโหว่ระดับกลาง ควรวางแผนแก้ไข")

            if summary["key_findings"]:
                summary["recommendations"].append(
                    "พบการแสวงหาประโยชน์ที่สำเร็จ ควรตรวจสอบระบบ")

            return summary

        except Exception as e:
            log.error(f"❌ สร้าง executive summary ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_technical_details(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายละเอียดทางเทคนิค"""
        try:
            technical_details = {
                "title": "Technical Details",
                "timestamp": datetime.now().isoformat(),
                "phases": {},
                "agents": {},
                "statistics": results.get("statistics", {}),
                "timeline": []
            }

            # รายละเอียด phases
            for phase_name, phase_data in results.get("phases", {}).items():
                technical_details["phases"][phase_name] = {
                    "name": phase_data.get("name", ""),
                    "status": phase_data.get("status", ""),
                    "success": phase_data.get("success", False),
                    "start_time": phase_data.get("start_time", ""),
                    "end_time": phase_data.get("end_time", ""),
                    "duration": phase_data.get("duration", 0),
                    "agents_used": phase_data.get("agents_used", []),
                    "results": phase_data.get("results", {}),
                    "errors": phase_data.get("errors", []),
                    "findings": phase_data.get("findings", []),
                    "vulnerabilities": phase_data.get("vulnerabilities", []),
                    "exploits": phase_data.get("exploits", [])
                }

            # รายละเอียด agents
            for agent_name, agent_data in results.get("agents", {}).items():
                technical_details["agents"][agent_name] = {
                    "name": agent_data.get("name", ""),
                    "status": agent_data.get("status", ""),
                    "success": agent_data.get("success", False),
                    "start_time": agent_data.get("start_time", ""),
                    "end_time": agent_data.get("end_time", ""),
                    "duration": agent_data.get("duration", 0),
                    "results": agent_data.get("results", {}),
                    "errors": agent_data.get("errors", []),
                    "findings": agent_data.get("findings", []),
                    "vulnerabilities": agent_data.get("vulnerabilities", []),
                    "exploits": agent_data.get("exploits", [])
                }

            # สร้าง timeline
            timeline = []
            for phase_name, phase_data in results.get("phases", {}).items():
                timeline.append({
                    "timestamp": phase_data.get("start_time", ""),
                    "event": f"Phase {phase_name} started",
                    "type": "phase_start",
                    "data": phase_data
                })

                timeline.append({
                    "timestamp": phase_data.get("end_time", ""),
                    "event": f"Phase {phase_name} completed",
                    "type": "phase_end",
                    "data": phase_data
                })

            # เรียง timeline ตาม timestamp
            timeline.sort(key=lambda x: x["timestamp"])
            technical_details["timeline"] = timeline

            return technical_details

        except Exception as e:
            log.error(f"❌ สร้าง technical details ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_vulnerability_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานช่องโหว่"""
        try:
            vulnerability_report = {
                "title": "Vulnerability Report",
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_vulnerabilities": len(results.get("vulnerabilities", [])),
                    "by_severity": {},
                    "by_type": {}
                },
                "vulnerabilities": results.get("vulnerabilities", []),
                "recommendations": []
            }

            # วิเคราะห์ vulnerabilities
            vulnerabilities = results.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown")
                vuln_type = vuln.get("type", "unknown")

                # นับตาม severity
                if severity not in vulnerability_report["summary"]["by_severity"]:
                    vulnerability_report["summary"]["by_severity"][severity] = 0
                vulnerability_report["summary"]["by_severity"][severity] += 1

                # นับตาม type
                if vuln_type not in vulnerability_report["summary"]["by_type"]:
                    vulnerability_report["summary"]["by_type"][vuln_type] = 0
                vulnerability_report["summary"]["by_type"][vuln_type] += 1

            # สร้างคำแนะนำ
            high_severity_count = vulnerability_report["summary"]["by_severity"].get(
                "high", 0)
            critical_severity_count = vulnerability_report["summary"]["by_severity"].get(
                "critical", 0)

            if critical_severity_count > 0:
                vulnerability_report["recommendations"].append(
                    "พบช่องโหว่ระดับวิกฤต ต้องแก้ไขด่วน")

            if high_severity_count > 0:
                vulnerability_report["recommendations"].append(
                    "พบช่องโหว่ระดับสูง ควรแก้ไขทันที")

            medium_severity_count = vulnerability_report["summary"]["by_severity"].get(
                "medium", 0)
            if medium_severity_count > 0:
                vulnerability_report["recommendations"].append(
                    "พบช่องโหว่ระดับกลาง ควรวางแผนแก้ไข")

            return vulnerability_report

        except Exception as e:
            log.error(f"❌ สร้าง vulnerability report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_exploit_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานการแสวงหาประโยชน์"""
        try:
            exploit_report = {
                "title": "Exploit Report",
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_exploits": len(results.get("exploits", [])),
                    "successful_exploits": 0,
                    "failed_exploits": 0,
                    "by_type": {}
                },
                "exploits": results.get("exploits", []),
                "recommendations": []
            }

            # วิเคราะห์ exploits
            exploits = results.get("exploits", [])
            for exploit in exploits:
                if exploit.get("success", False):
                    exploit_report["summary"]["successful_exploits"] += 1
                else:
                    exploit_report["summary"]["failed_exploits"] += 1

                exploit_type = exploit.get("type", "unknown")
                if exploit_type not in exploit_report["summary"]["by_type"]:
                    exploit_report["summary"]["by_type"][exploit_type] = 0
                exploit_report["summary"]["by_type"][exploit_type] += 1

            # สร้างคำแนะนำ
            if exploit_report["summary"]["successful_exploits"] > 0:
                exploit_report["recommendations"].append(
                    "พบการแสวงหาประโยชน์ที่สำเร็จ ควรตรวจสอบระบบ")

            if exploit_report["summary"]["failed_exploits"] > 0:
                exploit_report["recommendations"].append(
                    "พบการแสวงหาประโยชน์ที่ล้มเหลว ควรตรวจสอบระบบป้องกัน")

            return exploit_report

        except Exception as e:
            log.error(f"❌ สร้าง exploit report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_findings_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานการค้นพบ"""
        try:
            findings_report = {
                "title": "Findings Report",
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_findings": len(results.get("findings", [])),
                    "by_type": {},
                    "sensitive_findings": 0
                },
                "findings": results.get("findings", []),
                "recommendations": []
            }

            # วิเคราะห์ findings
            findings = results.get("findings", [])
            for finding in findings:
                finding_type = finding.get("type", "unknown")
                if finding_type not in findings_report["summary"]["by_type"]:
                    findings_report["summary"]["by_type"][finding_type] = 0
                findings_report["summary"]["by_type"][finding_type] += 1

                if "sensitive" in finding.get("description", "").lower():
                    findings_report["summary"]["sensitive_findings"] += 1

            # สร้างคำแนะนำ
            if findings_report["summary"]["sensitive_findings"] > 0:
                findings_report["recommendations"].append(
                    "พบข้อมูลที่ละเอียดอ่อน ควรตรวจสอบการเข้าถึง")

            return findings_report

        except Exception as e:
            log.error(f"❌ สร้าง findings report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_recommendations(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างคำแนะนำ"""
        try:
            recommendations = {
                "title": "Recommendations",
                "timestamp": datetime.now().isoformat(),
                "immediate_actions": [],
                "short_term_actions": [],
                "long_term_actions": [],
                "security_improvements": [],
                "monitoring_recommendations": []
            }

            # วิเคราะห์ vulnerabilities
            vulnerabilities = results.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low").lower()
                if severity == "critical":
                    recommendations["immediate_actions"].append({
                        "action": f"แก้ไขช่องโหว่ {vuln.get('type', '')} ที่ {vuln.get('location', '')}",
                        "reason": "ช่องโหว่ระดับวิกฤต",
                        "priority": "critical"
                    })
                elif severity == "high":
                    recommendations["immediate_actions"].append({
                        "action": f"แก้ไขช่องโหว่ {vuln.get('type', '')} ที่ {vuln.get('location', '')}",
                        "reason": "ช่องโหว่ระดับสูง",
                        "priority": "high"
                    })
                elif severity == "medium":
                    recommendations["short_term_actions"].append({
                        "action": f"แก้ไขช่องโหว่ {vuln.get('type', '')} ที่ {vuln.get('location', '')}",
                        "reason": "ช่องโหว่ระดับกลาง",
                        "priority": "medium"
                    })

            # วิเคราะห์ exploits
            exploits = results.get("exploits", [])
            for exploit in exploits:
                if exploit.get("success", False):
                    recommendations["immediate_actions"].append({
                        "action": f"ตรวจสอบการแสวงหาประโยชน์ {exploit.get('type', '')} ที่ {exploit.get('target', '')}",
                        "reason": "การแสวงหาประโยชน์สำเร็จ",
                        "priority": "high"
                    })

            # วิเคราะห์ findings
            findings = results.get("findings", [])
            for finding in findings:
                if "sensitive" in finding.get("description", "").lower():
                    recommendations["immediate_actions"].append({
                        "action": f"ตรวจสอบการเข้าถึงข้อมูลที่ละเอียดอ่อน: {finding.get('description', '')}",
                        "reason": "พบข้อมูลที่ละเอียดอ่อน",
                        "priority": "high"
                    })

            # คำแนะนำด้านความปลอดภัย
            recommendations["security_improvements"] = [
                "ใช้การเข้ารหัสข้อมูลที่แข็งแกร่ง",
                "ใช้การตรวจสอบสิทธิ์แบบหลายขั้นตอน",
                "ใช้การตรวจสอบการเข้าถึงแบบแยกส่วน",
                "ใช้การตรวจสอบความปลอดภัยแบบต่อเนื่อง"
            ]

            # คำแนะนำด้านการติดตาม
            recommendations["monitoring_recommendations"] = [
                "ติดตามการเข้าถึงระบบแบบ real-time",
                "ติดตามการเปลี่ยนแปลงไฟล์สำคัญ",
                "ติดตามการเข้าถึงข้อมูลที่ละเอียดอ่อน",
                "ติดตามการแสวงหาประโยชน์ที่อาจเกิดขึ้น"
            ]

            return recommendations

        except Exception as e:
            log.error(f"❌ สร้างคำแนะนำล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_full_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานแบบเต็ม"""
        try:
            full_report = {
                "title": "Full Security Assessment Report",
                "timestamp": datetime.now().isoformat(),
                "executive_summary": await self._generate_executive_summary(results),
                "technical_details": await self._generate_technical_details(results),
                "vulnerability_report": await self._generate_vulnerability_report(results),
                "exploit_report": await self._generate_exploit_report(results),
                "findings_report": await self._generate_findings_report(results),
                "recommendations": await self._generate_recommendations(results)
            }

            return full_report

        except Exception as e:
            log.error(f"❌ สร้าง full report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _save_json_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น JSON"""
        try:
            os.makedirs("reports", exist_ok=True)
            report_file = f"reports/{report_id}.json"

            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            log.info(f"📄 บันทึกรายงาน JSON: {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน JSON ล้มเหลว: {e}")

    async def _save_html_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น HTML"""
        try:
            # สร้าง HTML template
            html_content = await self._generate_html_content(report_data)

            os.makedirs("reports", exist_ok=True)
            report_file = f"reports/{report_id}.html"

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            log.info(f"📄 บันทึกรายงาน HTML: {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน HTML ล้มเหลว: {e}")

    async def _save_pdf_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น PDF"""
        try:
            # สร้าง HTML content ก่อน
            html_content = await self._generate_html_content(report_data)

            # ใช้ weasyprint หรือ library อื่นสำหรับสร้าง PDF
            # สำหรับตอนนี้ให้บันทึกเป็น HTML
            os.makedirs("reports", exist_ok=True)
            report_file = f"reports/{report_id}.html"

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            log.info(f"📄 บันทึกรายงาน PDF (HTML): {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน PDF ล้มเหลว: {e}")

    async def _generate_html_content(self, report_data: Dict[str, Any]) -> str:
        """สร้าง HTML content"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data.get('title', 'Security Assessment Report')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .vulnerability {{ background-color: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .exploit {{ background-color: #e6f3ff; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .finding {{ background-color: #f0f8e6; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .recommendation {{ background-color: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>{report_data.get('title', 'Security Assessment Report')}</h1>
    <p>Generated: {report_data.get('timestamp', '')}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report contains the results of a comprehensive security assessment.</p>
    </div>
    
    <h2>Vulnerabilities</h2>
    <div class="vulnerability">
        <p>Total vulnerabilities found: {len(report_data.get('vulnerabilities', []))}</p>
    </div>
    
    <h2>Exploits</h2>
    <div class="exploit">
        <p>Total exploits attempted: {len(report_data.get('exploits', []))}</p>
    </div>
    
    <h2>Findings</h2>
    <div class="finding">
        <p>Total findings: {len(report_data.get('findings', []))}</p>
    </div>
    
    <h2>Recommendations</h2>
    <div class="recommendation">
        <p>Please review the detailed recommendations in the full report.</p>
    </div>
</body>
</html>
            """

            return html_content

        except Exception as e:
            log.error(f"❌ สร้าง HTML content ล้มเหลว: {e}")
            return "<html><body><h1>Error generating report</h1></body></html>"

    def get_generated_reports(self) -> Dict[str, Any]:
        """รับรายการรายงานที่สร้างแล้ว"""
        return self.generated_reports

    def get_report(self, report_id: str) -> Dict[str, Any]:
        """รับรายงานตาม ID"""
        return self.generated_reports.get(report_id, {})
