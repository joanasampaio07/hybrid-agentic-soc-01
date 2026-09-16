import sqlite3
import json
import datetime
from pathlib import Path
from app.core.config import DB_PATH

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table: Alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        destination_ip TEXT,
        agent_name TEXT,
        rule_id TEXT,
        rule_level INTEGER,
        rule_description TEXT,
        mitre_id TEXT,
        mitre_technique TEXT,
        status TEXT, -- 'NEW', 'AUTO_CLOSED', 'NOTIFIED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'
        raw_payload TEXT
    )
    """)
    
    # Table: AI Investigations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY,
        alert_id TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        vt_score TEXT,
        abuseipdb_score INTEGER,
        abuseipdb_country TEXT,
        abuseipdb_isp TEXT,
        is_tor_exit INTEGER,
        ai_summary TEXT,
        risk_level TEXT, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        confidence_score INTEGER,
        recommended_actions TEXT,
        containment_status TEXT, -- 'PENDING', 'APPROVED', 'EXECUTED', 'SKIPPED'
        FOREIGN KEY (alert_id) REFERENCES alerts (id)
    )
    """)
    
    # Table: Containment Actions (Firewall blocks, host isolation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS containment_actions (
        id TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        action_type TEXT, -- 'BLOCK_IP', 'ISOLATE_HOST', 'DISABLE_USER'
        status TEXT, -- 'ACTIVE', 'REVOKED'
        reason TEXT,
        executed_by TEXT, -- 'AI_AUTONOMOUS', 'ANALYST_HUMAN'
        audit_log TEXT
    )
    """)
    
    # Table: App Settings (Dynamic overrides)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()

init_db()
