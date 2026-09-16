from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from app.simulator.attack_scenarios import attack_simulator
from app.api.routes_alerts import create_alert, AlertPayload

router = APIRouter(prefix="/api/simulator", tags=["simulator"])

class TriggerScenarioRequest(BaseModel):
    scenario: str # "ssh_brute_force", "privilege_escalation", "web_sqli_exploit", "fim_ransomware", "recon_port_scan"

@router.get("/scenarios")
def list_scenarios() -> Dict[str, Any]:
    return attack_simulator.SCENARIOS

@router.post("/trigger")
async def trigger_scenario(request: TriggerScenarioRequest, background_tasks: BackgroundTasks):
    if request.scenario not in attack_simulator.SCENARIOS:
        raise HTTPException(status_code=400, detail="Invalid scenario key")
        
    alert_raw = attack_simulator.generate(request.scenario)
    payload = AlertPayload(**alert_raw)
    
    res = await create_alert(payload, background_tasks)
    return {
        "success": True,
        "scenario": request.scenario,
        "scenario_name": attack_simulator.SCENARIOS[request.scenario]["name"],
        "alert": alert_raw,
        "triage_result": res
    }
