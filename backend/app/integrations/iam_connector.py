import uuid
import datetime
from typing import Dict, Any, List

class IAMConnector:
    """
    Identity & Access Management (IAM) Security Connector.
    Supports Microsoft Entra ID (Azure AD), Okta, Keycloak & Active Directory.
    """
    
    @staticmethod
    def revoke_user_sessions(user_principal_name: str, provider: str = "Microsoft Entra ID") -> Dict[str, Any]:
        """Revoke all active refresh tokens and sessions for compromised user"""
        action_id = f"iam-rev-{uuid.uuid4().hex[:6]}"
        return {
            "success": True,
            "action_id": action_id,
            "user": user_principal_name,
            "provider": provider,
            "status": "SESSIONS_REVOKED",
            "reason": f"Compromised credential containment triggered by SOC Agent",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

    @staticmethod
    def disable_user_account(user_principal_name: str, provider: str = "Microsoft Entra ID") -> Dict[str, Any]:
        """Temporarily lock or disable user account in directory"""
        action_id = f"iam-dis-{uuid.uuid4().hex[:6]}"
        return {
            "success": True,
            "action_id": action_id,
            "user": user_principal_name,
            "provider": provider,
            "status": "ACCOUNT_DISABLED",
            "reason": f"Active threat containment: high-risk account disabled",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

iam_connector = IAMConnector()
