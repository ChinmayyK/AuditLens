from typing import Optional, Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from models.base import get_db
from models.user import User, UserSession
from core.security import decode_token, hash_token
from datetime import datetime

security = HTTPBearer(auto_error=False)


def get_current_user_optional(
    request: Request,
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials],
        Depends(security)
    ],
    db: Session = Depends(get_db),
) -> Optional[User]:
    token = _extract_token(request, credentials)
    if not token:
        return None
    return _resolve_user(token, db)


def get_current_user(
    request: Request,
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials],
        Depends(security)
    ],
    db: Session = Depends(get_db),
) -> User:
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = _resolve_user(token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def _extract_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials]
) -> Optional[str]:
    # 1. Check Authorization header
    if credentials:
        return credentials.credentials

    # 2. Check Cookie
    return request.cookies.get("ss_access_token")


def require_plan(allowed_plans: list[str]):
    def _check(user: User = Depends(get_current_user)):
        if user.plan not in allowed_plans:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This feature requires one of: {', '.join(allowed_plans)} plan",
            )
        return user
    return _check


def _resolve_user(token: str,
                  db: Session) -> Optional[User]:
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
    except ValueError:
        return None

    token_hash = hash_token(token)
    session = db.query(UserSession).filter(
        UserSession.token_hash == token_hash,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow(),
    ).first()

    if not session:
        return None

    session.last_used = datetime.utcnow()
    db.commit()

    user = db.query(User).filter(
        User.id == user_id,
        User.is_active == True,
    ).first()

    return user
