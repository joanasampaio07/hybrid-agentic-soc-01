from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from app.agents.containment_agent import containment_agent
from app.api.websocket_manager import ws_manager
from app.api.routes_alerts import get_metrics_summary

router = APIRouter(prefix="/api/containment", tags=["containment"])

class BlockIPRequest(BaseModel):
    source_ip: str
    reason: str
    executed_by: str = "ANALYST_HUMAN"

class UnblockIPRequest(BaseModel):
    source_ip: str
    executed_by: str = "ANALYST_HUMAN"

@router.get("/blocks")
def list_blocks() -> List[Dict[str, Any]]:
    return containment_agent.list_active_blocks()

@router.post("/block")
async def block_ip(request: BlockIPRequest):
    result = containment_agent.block_ip(request.source_ip, request.reason, request.executed_by)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to block IP"))
        
    await ws_manager.broadcast("CONTAINMENT_ACTION", result)
    await ws_manager.broadcast("METRICS_UPDATE", get_metrics_summary())
    return result

@router.post("/unblock")
async def unblock_ip(request: UnblockIPRequest):
    result = containment_agent.unblock_ip(request.source_ip, request.executed_by)
    await ws_manager.broadcast("CONTAINMENT_ACTION", result)
    await ws_manager.broadcast("METRICS_UPDATE", get_metrics_summary())
    return result
