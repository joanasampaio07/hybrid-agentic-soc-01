import httpx
import uuid
import datetime
from typing import Dict, Any, Optional

class WazuhConnector:
    """
    Wazuh SIEM Connector.
    Handles webhook event parsing, Wazuh Manager API querying, and Active Response triggers.
    """
    
    @staticmethod
    def parse_wazuh_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw Wazuh alert JSON to standard SOC alert model"""
        rule = payload.get("rule", {})
        agent = payload.get("agent", {})
        data = payload.get("data", {})
        
        rule_id = str(rule.get("id", "100000"))
        rule_level = int(rule.get("level", 5))
        rule_desc = rule.get("description", "Wazuh Security Event")
        
        # MITRE extraction
        mitre = rule.get("mitre", {})
        mitre_ids = mitre.get("id", [])
        mitre_id = mitre_ids[0] if isinstance(mitre_ids, list) and mitre_ids else (mitre_ids if isinstance(mitre_ids, str) else "T1059")
        mitre_tactic = mitre.get("tactic", ["Execution"])[0] if isinstance(mitre.get("tactic"), list) and mitre.get("tactic") else "Execution"
        
        # Source IP extraction
        source_ip = data.get("srcip") or data.get("src_ip") or payload.get("srcip") or "185.220.101.45"
        dest_ip = data.get("dstip") or data.get("dst_ip") or "10.0.1.50"
        
        return {
            "id": f"wazuh-{payload.get('id', uuid.uuid4().hex[:8])}",
            "timestamp": payload.get("timestamp") or datetime.datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "agent_name": agent.get("name", "wazuh-agent-linux"),
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_description": rule_desc,
            "mitre_id": mitre_id,
            "mitre_technique": mitre_tactic,
            "raw_payload": str(payload)
        }

    async def trigger_active_response(self, manager_url: str, auth_token: str, agent_id: str, command: str) -> Dict[str, Any]:
        """Trigger Wazuh Active Response script on agent"""
        try:
            headers = {"Authorization": f"Bearer {auth_token}"}
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                res = await client.put(
                    f"{manager_url}/active-response",
                    headers=headers,
                    json={"command": command, "agents_list": [agent_id]}
                )
                return {"success": res.status_code == 200, "status_code": res.status_code}
        except Exception as e:
            return {"success": False, "error": str(e)}

wazuh_connector = WazuhConnector()
