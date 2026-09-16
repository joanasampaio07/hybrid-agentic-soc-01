from typing import Dict, Any, List
from app.core.database import get_db_connection

class CorrelationEngine:
    """
    Multi-Dimensional Correlation Engine
    Tracks:
    1. IP Frequency & Reputation Evolution
    2. Agent Target Density (which servers are under attack)
    3. MITRE ATT&CK Chain Progression (Recon -> Access -> PrivEsc -> Impact)
    """
    
    @staticmethod
    def get_ip_history(source_ip: str) -> Dict[str, Any]:
        if not source_ip or source_ip == "127.0.0.1" or source_ip == "localhost":
            return {"total_alerts": 0, "levels": [], "chains": []}
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, rule_level, rule_description, mitre_id, status
            FROM alerts
            WHERE source_ip = ?
            ORDER BY timestamp DESC
            LIMIT 20
        """, (source_ip,))
        rows = cursor.fetchall()
        conn.close()
        
        alerts = [dict(r) for r in rows]
        total = len(alerts)
        levels = [r["rule_level"] for r in alerts]
        mitres = list(set([r["mitre_id"] for r in alerts if r["mitre_id"]]))
        
        # Detect attack escalation chain (e.g. low reconnaissance -> high brute force)
        has_escalation = False
        if len(levels) >= 2 and min(levels) <= 6 and max(levels) >= 12:
            has_escalation = True
            
        return {
            "source_ip": source_ip,
            "total_alerts": total,
            "recent_levels": levels[:5],
            "mitre_techniques": mitres,
            "has_escalation_chain": has_escalation,
            "history": alerts
        }
        
    @staticmethod
    def get_mitre_coverage() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT mitre_id, mitre_technique, COUNT(*) as alert_count, MAX(rule_level) as max_severity
            FROM alerts
            WHERE mitre_id IS NOT NULL AND mitre_id != ''
            GROUP BY mitre_id, mitre_technique
            ORDER BY alert_count DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        default_matrix = [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "count": 0, "active": False},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "count": 0, "active": False},
            {"id": "T1136", "name": "Create Account", "tactic": "Persistence", "count": 0, "active": False},
            {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access", "count": 0, "active": False},
            {"id": "T1222", "name": "File Permissions Modification", "tactic": "Defense Evasion", "count": 0, "active": False},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "count": 0, "active": False},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "count": 0, "active": False},
        ]
        
        active_counts = {r["mitre_id"]: r["alert_count"] for r in rows}
        for item in default_matrix:
            if item["id"] in active_counts:
                item["count"] = active_counts[item["id"]]
                item["active"] = True
                
        return default_matrix

correlation_engine = CorrelationEngine()
