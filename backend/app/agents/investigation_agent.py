import json
import httpx
from typing import Dict, Any, List
from app.core.config import settings

class InvestigationAgent:
    """
    AI Threat Investigation Agent.
    Synthesizes SIEM alert context, Threat Intel (VT + AbuseIPDB), and
    multi-dimensional correlation to produce a structured 3-part SOC Incident Report.
    """
    
    async def investigate(self, alert: Dict[str, Any], ti_data: Dict[str, Any], correlation: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self._build_prompt(alert, ti_data, correlation)
        
        provider = settings.LLM_PROVIDER.lower()
        ai_response = None
        
        # 1. Ollama (Local LLM - Mistral/Llama3)
        if provider == "ollama" or (settings.OLLAMA_BASE_URL and provider != "demo"):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    payload = {
                        "model": settings.OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False
                    }
                    resp = await client.post(f"{settings.OLLAMA_BASE_URL}/api/generate", json=payload)
                    if resp.status_code == 200:
                        ai_response = resp.json().get("response")
            except Exception as e:
                print(f"[InvestigationAgent] Ollama connection failed: {e}. Falling back to demo generator.")
                
        # 2. Google Gemini
        if not ai_response and provider == "gemini" and settings.GEMINI_API_KEY:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        candidates = resp.json().get("candidates", [])
                        if candidates:
                            ai_response = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            except Exception as e:
                print(f"[InvestigationAgent] Gemini error: {e}")

        # 3. High-Quality Deterministic Demo Mode (Zero API tokens needed, perfect for video/LinkedIn/client demos)
        if not ai_response:
            ai_response = self._generate_demo_investigation(alert, ti_data, correlation)
            
        risk_level = "CRITICAL" if ti_data.get("abuseipdb_score", 0) >= 80 or alert.get("rule_level", 0) >= 13 else "HIGH"
        confidence = max(85, min(99, int(ti_data.get("abuseipdb_score", 70))))
        
        recommended_actions = [
            f"Block source IP {alert.get('source_ip')} at perimeter firewall / AWS Security Group",
            "Force credential reset for targeted accounts and enforce MFA",
            "Audit authentication logs for successful sessions from this IP in the last 72 hours",
            "Add IOC to centralized SIEM blocklist and isolate affected endpoint if persistence is detected"
        ]
        
        return {
            "ai_summary": ai_response,
            "risk_level": risk_level,
            "confidence_score": confidence,
            "recommended_actions": json.dumps(recommended_actions),
            "containment_status": "PENDING"
        }
        
    def _build_prompt(self, alert: Dict[str, Any], ti_data: Dict[str, Any], correlation: Dict[str, Any]) -> str:
        return f"""You are an elite Tier-3 SOC Lead Security AI Agent.
Analyze the following security incident and generate a structured 3-part SOC investigation report.

[ALERT CONTEXT]
- Rule ID: {alert.get('rule_id')}
- Severity Level: {alert.get('rule_level')}
- Description: {alert.get('rule_description')}
- Target Host / Agent: {alert.get('agent_name')}
- MITRE Technique: {alert.get('mitre_id')} ({alert.get('mitre_technique')})
- Source IP: {alert.get('source_ip')}

[THREAT INTELLIGENCE]
- VirusTotal Detections: {ti_data.get('vt_score')}
- AbuseIPDB Confidence Score: {ti_data.get('abuseipdb_score')}%
- Origin Country: {ti_data.get('abuseipdb_country')}
- ISP / ASN: {ti_data.get('abuseipdb_isp')}
- Is Tor Exit Node: {ti_data.get('is_tor_exit')}

[CORRELATION TELEMETRY]
- Total Alerts from this IP: {correlation.get('total_alerts')}
- Multi-Stage Attack Chain Detected: {correlation.get('has_escalation_chain')}

Format the output strictly as:
1. THREAT SUMMARY: (Concise incident description grounded with threat intel scores)
2. RISK ASSESSMENT: (Impact, urgency, blast radius analysis)
3. RECOMMENDED CONTAINMENT ACTIONS: (Step-by-step containment instructions)
"""

    def _generate_demo_investigation(self, alert: Dict[str, Any], ti_data: Dict[str, Any], correlation: Dict[str, Any]) -> str:
        ip = alert.get("source_ip", "Unknown")
        vt = ti_data.get("vt_score", "0/91")
        abuse = ti_data.get("abuseipdb_score", 0)
        country = ti_data.get("abuseipdb_country", "Unknown")
        isp = ti_data.get("abuseipdb_isp", "Unknown")
        is_tor = "Yes (Tor Exit Node)" if ti_data.get("is_tor_exit") else "No"
        desc = alert.get("rule_description", "Suspicious attack activity")
        mitre = alert.get("mitre_id", "T1110")
        
        return f"""SECURITY INCIDENT INVESTIGATION REPORT — {mitre}
======================================================================
1. THREAT SUMMARY:
Active hostile activity detected targeting '{alert.get('agent_name', 'production-server')}'.
- Trigger: {desc} (Level {alert.get('rule_level', 12)})
- Attacker IP: {ip} [Origin: {country} | ISP: {isp} | Tor Relay: {is_tor}]
- VirusTotal Detection: {vt} malicious engines flagged
- AbuseIPDB Abuse Confidence: {abuse}%
- Historical Frequency: {correlation.get('total_alerts', 1)} correlated events logged in the last 24h.

2. RISK ASSESSMENT:
CRITICAL — High likelihood of credential harvesting, unauthorized privilege escalation, or lateral movement attempt. The combination of high AbuseIPDB confidence score ({abuse}%) and automated reconnaissance indicates an active threat actor requiring immediate containment to prevent lateral blast radius expansion.

3. RECOMMENDED CONTAINMENT ACTIONS:
• [Automated] Execute perimeter IP Block on {ip} across AWS Security Groups / Firewall.
• [Identity] Invalidate all active user sessions initiated within the last 4 hours on '{alert.get('agent_name', 'host')}'.
• [Forensics] Perform memory & process tree inspection for newly spawned bash/powershell subprocesses.
• [Policy] Enforce SSH key-only auth and MFA verification on all administrative jumpboxes.
"""

investigation_agent = InvestigationAgent()
