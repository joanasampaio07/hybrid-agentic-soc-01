from typing import Dict, Any, Tuple

class RuleEngine:
    """
    Deterministic Rule-Based Triage Engine.
    Routes alerts by severity level and MITRE pattern.
    - Level 0-6: LOW -> Auto-close & audit log
    - Level 7-11: MEDIUM -> Analyst Notification & sheet log
    - Level 12+: HIGH / CRITICAL -> Full Agentic AI Investigation + Threat Intel
    """
    
    @staticmethod
    def evaluate(alert: Dict[str, Any]) -> Tuple[str, str, str]:
        level = int(alert.get("rule_level", 0))
        rule_desc = alert.get("rule_description", "").lower()
        mitre_id = alert.get("mitre_id", "")
        
        # Override heuristics for known critical attack techniques
        if mitre_id in ["T1110", "T1078", "T1136", "T1190", "T1486"] and level < 12:
            # Upgrade if active brute force / privesc / ransomware signature
            if "brute force" in rule_desc or "privilege" in rule_desc or "ransomware" in rule_desc:
                level = 12
        
        if level <= 6:
            tier = "LOW"
            action = "AUTO_CLOSE"
            rationale = f"Level {level} benign/low-risk event. Auto-triaged and archived to audit log."
        elif 7 <= level <= 11:
            tier = "MEDIUM"
            action = "NOTIFY_ANALYST"
            rationale = f"Level {level} suspicious event. Dispatched notification to SOC analysts with telemetry."
        else:
            tier = "HIGH"
            action = "AI_INVESTIGATION"
            rationale = f"Level {level} high-severity anomaly detected. Full multi-agent AI threat investigation triggered."
            
        return tier, action, rationale

rules_engine = RuleEngine()
