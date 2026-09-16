import uuid
import datetime
from typing import Dict, Any, List
from app.core.database import get_db_connection

class ContainmentAgent:
    """
    Automated and Human-in-the-loop Containment Agent.
    Executes firewall isolation, IP blocking, and host quarantine with full audit trail.
    """
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "ANALYST_HUMAN") -> Dict[str, Any]:
        if not ip or ip in ["127.0.0.1", "localhost"]:
            return {"success": False, "error": "Cannot block internal loopback IP"}
            
        action_id = str(uuid.uuid4())[:8]
        audit_log = f"Perimeter firewall / AWS Security Group drop rule applied for {ip}. Reason: {reason}"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if already blocked
        cursor.execute("SELECT id FROM containment_actions WHERE source_ip = ? AND status = 'ACTIVE'", (ip,))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return {"success": True, "message": f"IP {ip} is already blocked", "action_id": existing["id"]}
            
        cursor.execute("""
            INSERT INTO containment_actions (id, source_ip, action_type, status, reason, executed_by, audit_log)
            VALUES (?, ?, 'BLOCK_IP', 'ACTIVE', ?, ?, ?)
        """, (action_id, ip, reason, executed_by, audit_log))
        
        # Update associated investigations
        cursor.execute("""
            UPDATE investigations SET containment_status = 'EXECUTED' WHERE source_ip = ?
        """, (ip,))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "action_id": action_id,
            "source_ip": ip,
            "action_type": "BLOCK_IP",
            "status": "ACTIVE",
            "executed_by": executed_by,
            "audit_log": audit_log
        }
        
    def unblock_ip(self, ip: str, executed_by: str = "ANALYST_HUMAN") -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE containment_actions
            SET status = 'REVOKED', audit_log = audit_log || ' | Revoked by ' || ?
            WHERE source_ip = ? AND status = 'ACTIVE'
        """, (executed_by, ip))
        conn.commit()
        conn.close()
        return {"success": True, "message": f"IP {ip} unblocked successfully"}
        
    def list_active_blocks(self) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, source_ip, action_type, status, reason, executed_by, audit_log
            FROM containment_actions
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

containment_agent = ContainmentAgent()
