import os
import hashlib
import hmac
import uuid
import datetime
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status, Header, Request
from pydantic import BaseModel
from app.core.database import get_db_connection

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cyber-soc-enterprise-super-secret-key-2026")
DEFAULT_ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = uuid.uuid4().hex[:16]
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt, key_hex = hashed_password.split('$')
        computed = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(computed.hex(), key_hex)
    except Exception:
        return False

def init_auth_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'ADMIN',
        full_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    
    # Create default admin if table is empty
    cursor.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,))
    if not cursor.fetchone():
        hashed = hash_password(DEFAULT_ADMIN_PASS)
        cursor.execute("""
            INSERT INTO users (id, username, password_hash, role, full_name)
            VALUES (?, ?, ?, 'ADMIN', 'SOC Lead Security Officer')
        """, (str(uuid.uuid4())[:8], DEFAULT_ADMIN_USER, hashed))
    
    conn.commit()
    conn.close()

def create_user_session(user_id: str) -> str:
    token = f"soc_sec_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO active_sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    conn.commit()
    conn.close()
    return token

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    if token.startswith("Bearer "):
        token = token[7:]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.role, u.full_name, u.created_at
        FROM active_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    # Check Authorization Header or Cookie
    token = authorization
    if not token:
        token = request.cookies.get("soc_token")
        
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

init_auth_db()
