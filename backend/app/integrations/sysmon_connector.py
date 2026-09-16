import uuid
import datetime
from typing import Dict, Any

class SysmonConnector:
    """
    Windows Sysmon & Event Log Connector.
    Ingests and normalizes Sysmon Event IDs (1, 3, 7, 11, 22).
    """
    
    SYSMON_EVENT_MAP = {
        1: {"name": "Process Creation", "level": 11, "mitre": "T1059", "tactic": "Command and Scripting Interpreter"},
        3: {"name": "Network Connection", "level": 12, "mitre": "T1071", "tactic": "Application Layer Protocol / C2"},
        7: {"name": "Image Loaded (DLL Injection)", "level": 13, "mitre": "T1055", "tactic": "Process Injection"},
        11: {"name": "File Create (Ransomware / Dropper)", "level": 14, "mitre": "T1486", "tactic": "Impact / Data Encryption"},
        22: {"name": "DNS Query (DGA / C2 Lookup)", "level": 12, "mitre": "T1071.004", "tactic": "DNS Tunneling"}
    }
    
    @classmethod
    def parse_sysmon_event(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        event_id = int(event.get("EventID") or event.get("event_id") or 1)
        event_info = cls.SYSMON_EVENT_MAP.get(event_id, {"name": "Generic Sysmon Event", "level": 8, "mitre": "T1059", "tactic": "Execution"})
        
        computer = event.get("Computer") or event.get("host") or "WIN-CORP-DC01"
        image = event.get("Image") or event.get("process_name") or "powershell.exe"
        cmd = event.get("CommandLine") or event.get("command_line") or "powershell.exe -enc SQBFAFgA..."
        dest_ip = event.get("DestinationIp") or event.get("dest_ip") or "185.220.101.45"
        src_ip = event.get("SourceIp") or event.get("src_ip") or "10.0.1.15"
        user = event.get("User") or "NT AUTHORITY\\SYSTEM"
        
        desc = f"Sysmon Event {event_id} ({event_info['name']}): Process '{image}' triggered by '{user}'. Command: {cmd[:60]}..."
        
        return {
            "id": f"sysmon-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": dest_ip if event_id in [3, 22] else src_ip,
            "destination_ip": src_ip if event_id in [3, 22] else dest_ip,
            "agent_name": computer,
            "rule_id": f"SYSMON-{event_id}",
            "rule_level": event_info["level"],
            "rule_description": desc,
            "mitre_id": event_info["mitre"],
            "mitre_technique": event_info["tactic"],
            "raw_payload": str(event)
        }

sysmon_connector = SysmonConnector()
