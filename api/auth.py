import os
import jwt
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from database import get_user_by_email, get_user_by_id, get_user_by_api_key, verify_password, create_user

JWT_SECRET = os.getenv("SCAMSHIELD_JWT_SECRET", "scamshield-super-secure-production-signature-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

security_bearer = HTTPBearer(auto_error=False)

def create_access_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(user["password_hash"], password):
        return None
    return user

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> Optional[dict]:
    if not credentials or not credentials.credentials:
        return None
    token = credentials.credentials
    # Check if this is an API key (starts with scam_ak_)
    if token.startswith("scam_ak_"):
        user = get_user_by_api_key(token)
        if user and user.get("is_active"):
            return user
        return None
        
    payload = decode_access_token(token)
    if not payload:
        return None
    user_id = int(payload.get("sub", 0))
    user = get_user_by_id(user_id)
    if not user or not user.get("is_active"):
        return None
    return user

def require_auth(user: Optional[dict] = Depends(get_current_user)) -> dict:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in or provide a valid Bearer token / API key."
        )
    return user

def require_role(allowed_roles: list[str]):
    def role_checker(user: dict = Depends(require_auth)) -> dict:
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {', '.join(allowed_roles)}. Your role is: {user.get('role')}."
            )
        return user
    return role_checker
