from fastapi import APIRouter, HTTPException, Depends, Response, Header
from pydantic import BaseModel
from typing import Dict, Any, Optional
from app.core.database import get_db_connection
from app.core.auth import (
    verify_password, create_user_session, require_auth, get_user_from_token
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    access_token: str
    user: Dict[str, Any]

@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, response: Response):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, role, full_name FROM users WHERE username = ?", (req.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas / Invalid credentials")
        
    token = create_user_session(user["id"])
    
    # Set HttpOnly session cookie
    response.set_cookie(
        key="soc_token",
        value=token,
        httponly=True,
        max_age=86400 * 7, # 7 days
        samesite="lax"
    )
    
    user_info = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "full_name": user["full_name"]
    }
    
    return {
        "success": True,
        "access_token": token,
        "user": user_info
    }

@router.get("/me")
def get_me(user: Dict[str, Any] = Depends(require_auth)):
    return {"authenticated": True, "user": user}

@router.post("/logout")
def logout(response: Response, authorization: Optional[str] = Header(None)):
    response.delete_cookie("soc_token")
    return {"success": True, "message": "Logged out successfully"}
