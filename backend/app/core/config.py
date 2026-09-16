import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = str(DATA_DIR / "soc_database.sqlite")

class Settings(BaseModel):
    PROJECT_NAME: str = "Enterprise Hybrid Agentic SOC"
    VERSION: str = "2.0.0"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DB_URL: str = DB_PATH
    
    # LLM Settings
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "demo")  # "demo", "gemini", "ollama", "openai"
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    
    # Threat Intel API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # Notification Integrations
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    EMAIL_ALERT_RECIPIENT: str = os.getenv("EMAIL_ALERT_RECIPIENT", "soc-team@enterprise.local")
    
    # Automation & Auto-containment
    AUTO_CONTAINMENT_ENABLED: bool = os.getenv("AUTO_CONTAINMENT_ENABLED", "false").lower() == "true"
    AUTO_CONTAINMENT_MIN_SEVERITY: int = 12

settings = Settings()
