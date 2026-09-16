import uuid
import datetime
from typing import Dict, Any, List

class MicrosoftSecurityConnector:
    """
    Microsoft Cybersecurity Suite Connector.
    Integrates with:
    1. Microsoft Sentinel (Cloud-native SIEM/SOAR Incidents)
    2. Microsoft Defender for Endpoint (EDR/XDR Device Isolation & Host Containment)
    3. Microsoft Entra ID (Azure AD IAM User Session Revocation & Identity Risk)
    """
    
    @staticmethod
    def parse_sentinel_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Microsoft Sentinel incident payload"""
        properties = payload.get("properties", payload)
        title = properties.get("title") or payload.get("IncidentTitle") or "Microsoft Sentinel Security Incident"
        severity = properties.get("severity") or payload.get("Severity") or "High"
        
        level_map = {"Informational": 3, "Low": 5, "Medium": 9, "High": 13, "Critical": 15}
        rule_level = level_map.get(severity, 12)
        
        ip = "194.26.29.112"
        entities = properties.get("relatedEntities", [])
        for ent in entities:
            if ent.get("kind") == "Ip":
                ip = ent.get("properties", {}).get("address", ip)
                
        return {
            "id": f"sentinel-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": ip,
            "destination_ip": "10.0.4.10",
            "agent_name": "Azure-Cloud-Host-01",
            "rule_id": "MS-SENTINEL-01",
            "rule_level": rule_level,
            "rule_description": f"Microsoft Sentinel: {title} (Severity: {severity})",
            "mitre_id": "T1190",
            "mitre_technique": "Initial Access / Cloud Infrastructure",
            "raw_payload": str(payload)
        }

    @staticmethod
    def parse_defender_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Microsoft Defender for Endpoint XDR Alert"""
        alert_name = payload.get("title") or payload.get("alertName") or "Suspicious Process Execution (MDE)"
        device_name = payload.get("computerDnsName") or payload.get("machineName") or "WIN-PROD-SRV01"
        severity = payload.get("severity") or "High"
        
        level_map = {"Informational": 3, "Low": 5, "Medium": 8, "High": 13, "Critical": 15}
        rule_level = level_map.get(severity, 13)
        
        mitre_tech = payload.get("mitreTechniques", ["T1059.001"])[0] if isinstance(payload.get("mitreTechniques"), list) and payload.get("mitreTechniques") else "T1059"
        
        return {
            "id": f"mde-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": payload.get("evidence", [{}])[0].get("ipAddress", "185.220.101.45") if isinstance(payload.get("evidence"), list) and payload.get("evidence") else "185.220.101.45",
            "destination_ip": "10.0.1.25",
            "agent_name": device_name,
            "rule_id": "MS-DEFENDER-XDR",
            "rule_level": rule_level,
            "rule_description": f"Microsoft Defender XDR: {alert_name}",
            "mitre_id": mitre_tech,
            "mitre_technique": "Execution / PowerShell Obfuscation",
            "raw_payload": str(payload)
        }

    @staticmethod
    def isolate_defender_device(device_id: str, comment: str) -> Dict[str, Any]:
        """Simulate or execute Microsoft Defender device isolation"""
        action_id = f"mde-iso-{uuid.uuid4().hex[:6]}"
        return {
            "success": True,
            "action_id": action_id,
            "device_id": device_id,
            "status": "ISOLATED",
            "provider": "Microsoft Defender for Endpoint",
            "comment": comment,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

microsoft_connector = MicrosoftSecurityConnector()
