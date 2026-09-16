import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.database import init_db, get_db_connection
from app.api.routes_alerts import router as alerts_router
from app.api.routes_simulator import router as simulator_router
from app.api.routes_containment import router as containment_router
from app.api.routes_settings import router as settings_router
from app.api.routes_auth import router as auth_router
from app.api.routes_integrations import router as integrations_router
from app.api.websocket_manager import ws_manager

# Initialize DB tables
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-Grade Enterprise Hybrid Agentic SOC with Autonomous AI Investigation and Real-time Command Center."
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(simulator_router)
app.include_router(containment_router)
app.include_router(settings_router)
app.include_router(integrations_router)

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo or heartbeat
            await websocket.send_text(f'{{"type":"PONG"}}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Serve Frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Enterprise Hybrid Agentic SOC API is running. UI building..."}

# Startup event to seed initial sample telemetry if empty
@app.on_event("startup")
async def seed_initial_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
    count = cursor.fetchone()["cnt"]
    if count == 0:
        cursor.execute("""
            INSERT INTO alerts (id, source_ip, destination_ip, agent_name, rule_id, rule_level, rule_description, mitre_id, mitre_technique, status)
            VALUES 
            ('alert-seed-01', '185.220.101.45', '10.0.1.50', 'prod-auth-gateway-01', '100001', 12, 'High Risk: Multiple SSH brute force attempts (Tor Exit Node)', 'T1110', 'Brute Force', 'CONTAINED'),
            ('alert-seed-02', '198.51.100.12', '10.0.0.1', 'perimeter-firewall', '100005', 4, 'Low Risk: ICMP Ping Sweep / Reconnaissance', 'T1046', 'Network Service Discovery', 'AUTO_CLOSED'),
            ('alert-seed-03', '87.152.6.217', '10.0.2.14', 'prod-db-cluster-02', '100002', 13, 'High Risk: Sudoers file modified & rogue account created', 'T1136', 'Create Account', 'INVESTIGATED'),
            ('alert-seed-04', '203.0.113.44', '10.0.0.80', 'web-nginx-01', '100003', 8, 'Medium Risk: Apache 404 scan probe', 'T1190', 'Exploit Public-Facing Application', 'NOTIFIED')
        """)
        
        cursor.execute("""
            INSERT INTO containment_actions (id, source_ip, action_type, status, reason, executed_by, audit_log)
            VALUES ('block-01', '185.220.101.45', 'BLOCK_IP', 'ACTIVE', 'Autonomous mitigation of Tor Exit Node SSH Brute Force (VT 17/91, Abuse 100%)', 'AI_AUTONOMOUS', 'Blocked at AWS Security Group & Perimeter iptables')
        """)
        
        cursor.execute("""
            INSERT INTO investigations (
                id, alert_id, source_ip, vt_score, abuseipdb_score, abuseipdb_country, abuseipdb_isp, is_tor_exit,
                ai_summary, risk_level, confidence_score, recommended_actions, containment_status
            ) VALUES (
                'inv-seed-01', 'alert-seed-01', '185.220.101.45', '17/91', 100, 'DE', 'Tor Exit Relay / For-Privacy', 1,
                'THREAT SUMMARY: High-volume SSH brute force attack originated from verified Tor exit node 185.220.101.45.
RISK ASSESSMENT: CRITICAL — Active adversary attempting credential stuffing against authentication gateway.
RECOMMENDED ACTIONS: Perimeter IP drop executed automatically.',
                'CRITICAL', 99, '["Block source IP at perimeter firewall", "Enforce SSH key-only auth", "Audit auth logs for previous 72h"]', 'EXECUTED'
            )
        """)
        conn.commit()
    conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
