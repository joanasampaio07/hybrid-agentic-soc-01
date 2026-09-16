from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, Optional
from app.core.config import settings

router = APIRouter(prefix="/api/settings", tags=["settings"])

class UpdateSettingsRequest(BaseModel):
    llm_provider: Optional[str] = None
    ollama_base_url: Optional[str] = None
    ollama_model: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    auto_containment_enabled: Optional[bool] = None

@router.get("")
def get_current_settings() -> Dict[str, Any]:
    return {
        "llm_provider": settings.LLM_PROVIDER,
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "ollama_model": settings.OLLAMA_MODEL,
        "has_gemini_key": bool(settings.GEMINI_API_KEY),
        "has_openai_key": bool(settings.OPENAI_API_KEY),
        "has_virustotal_key": bool(settings.VIRUSTOTAL_API_KEY),
        "has_abuseipdb_key": bool(settings.ABUSEIPDB_API_KEY),
        "auto_containment_enabled": settings.AUTO_CONTAINMENT_ENABLED,
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

@router.post("")
def update_settings(req: UpdateSettingsRequest) -> Dict[str, Any]:
    if req.llm_provider is not None:
        settings.LLM_PROVIDER = req.llm_provider
    if req.ollama_base_url is not None:
        settings.OLLAMA_BASE_URL = req.ollama_base_url
    if req.ollama_model is not None:
        settings.OLLAMA_MODEL = req.ollama_model
    if req.gemini_api_key is not None:
        settings.GEMINI_API_KEY = req.gemini_api_key
    if req.openai_api_key is not None:
        settings.OPENAI_API_KEY = req.openai_api_key
    if req.virustotal_api_key is not None:
        settings.VIRUSTOTAL_API_KEY = req.virustotal_api_key
    if req.abuseipdb_api_key is not None:
        settings.ABUSEIPDB_API_KEY = req.abuseipdb_api_key
    if req.auto_containment_enabled is not None:
        settings.AUTO_CONTAINMENT_ENABLED = req.auto_containment_enabled
        
    return {"success": True, "message": "Settings updated successfully"}
