import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from models.base import get_db
from models import scan  # noqa: F401
from models.user import User, UserSession, AuditLog
from schemas.auth import (
    GoogleVerifyRequest, GoogleVerifyResponse,
    CompleteSignupRequest, LoginRequest, SignupRequest,
    TokenResponse, UserResponse,
    MeResponse, PasswordStrengthResponse,
)
from core.security import (
    hash_password, verify_password,
    create_access_token, hash_token,
    validate_password_strength,
)
from core.google_auth import verify_google_token
from core.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

JWT_EXPIRE_DAYS = int(os.getenv("JWT_EXPIRE_DAYS", "7"))
COOKIE_NAME = "ss_access_token"
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development") == "production"


def _set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax" if not IS_PRODUCTION else "strict",
        max_age=JWT_EXPIRE_DAYS * 86400,
    )


def _clear_auth_cookie(response: Response):
    response.delete_cookie(
        key=COOKIE_NAME,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax" if not IS_PRODUCTION else "strict",
    )


def _create_session(
    user: User,
    db: Session,
    request: Request,
) -> str:
    token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        plan=user.plan,
    )
    token_hash = hash_token(token)
    expires = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)

    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        expires_at=expires,
    )
    db.add(session)

    user.last_login = datetime.utcnow()
    db.commit()

    return token


def _log_action(
    db: Session,
    action: str,
    user_id=None,
    resource=None,
    resource_id=None,
    request: Request = None,
    metadata: dict = None,
):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        metadata_=metadata,
    )
    db.add(log)
    db.commit()


from sqlalchemy import or_

@router.post(
    "/google/verify",
    response_model=GoogleVerifyResponse,
    summary="Verify Google OAuth credential",
)
async def google_verify(
    payload: GoogleVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    try:
        google_user = await verify_google_token(
            payload.credential
        )
        
        # Security check: Ensure we got a valid identity
        if not google_user.get("google_id") or not google_user.get("email"):
            raise ValueError("Google identity could not be verified (missing sub/email)")

        # Check by google_id OR email to prevent IntegrityError
        existing = db.query(User).filter(
            or_(
                User.google_id == google_user["google_id"],
                User.email == google_user["email"]
            )
        ).first()

        if existing:
            # Automatic Account Linking
            changed = False
            if not existing.google_id:
                existing.google_id = google_user["google_id"]
                changed = True
            if not existing.avatar_url and google_user.get("avatar_url"):
                existing.avatar_url = google_user["avatar_url"]
                changed = True
            if google_user.get("email_verified") and not existing.is_verified:
                existing.is_verified = True
                changed = True
            
            if changed:
                db.commit()

            if existing.hashed_password:
                token = _create_session(existing, db, request)
                _set_auth_cookie(response, token)
                _log_action(db, "google_login",
                            user_id=existing.id, request=request)
                return GoogleVerifyResponse(
                    status="existing_user",
                    google_id=google_user["google_id"],
                    email=existing.email,
                    full_name=existing.full_name,
                    avatar_url=existing.avatar_url,
                    requires_password=False,
                    access_token=token,
                    user=UserResponse.model_validate(existing),
                )
    except Exception as e:
        # In case of crash, we catch it here to prevent 500 without info
        print(f"CRITICAL AUTH ERROR: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication error: {str(e)}"
        )

    if existing and not existing.hashed_password:
        return GoogleVerifyResponse(
            status="incomplete",
            google_id=google_user["google_id"],
            email=existing.email,
            full_name=existing.full_name,
            avatar_url=existing.avatar_url,
            requires_password=True,
        )

    new_user = User(
        email=google_user["email"],
        full_name=google_user["full_name"] or
                  google_user["email"].split("@")[0],
        avatar_url=google_user["avatar_url"],
        google_id=google_user["google_id"],
        is_verified=google_user.get("email_verified", False),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    _log_action(db, "google_verify_new",
                user_id=new_user.id, request=request)

    return GoogleVerifyResponse(
        status="new_user",
        google_id=google_user["google_id"],
        email=new_user.email,
        full_name=new_user.full_name,
        avatar_url=new_user.avatar_url,
        requires_password=True,
    )


@router.post(
    "/signup/complete",
    response_model=TokenResponse,
    summary="Complete signup - set password",
)
async def complete_signup(
    payload: CompleteSignupRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(
        User.google_id == payload.google_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found. Complete Google verification first.",
        )

    if user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account already complete. Please log in.",
        )

    strength = validate_password_strength(payload.password)
    if not strength["valid"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password too weak: {', '.join(strength['errors'])}",
        )

    user.hashed_password = hash_password(payload.password)
    user.is_active = True
    db.commit()
    db.refresh(user)

    token = _create_session(user, db, request)
    _set_auth_cookie(response, token)
    _log_action(db, "signup_complete",
                user_id=user.id, request=request)

    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRE_DAYS * 86400,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/signup",
    response_model=TokenResponse,
    summary="Direct email + password signup",
)
async def signup(
    payload: SignupRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(
        User.email == payload.email
    ).first()

    if existing and existing.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists. Please log in.",
        )

    strength = validate_password_strength(payload.password)
    if not strength["valid"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password too weak: {', '.join(strength['errors'])}",
        )

    user = existing or User(
        email=payload.email,
        full_name=payload.full_name,
    )

    user.full_name = payload.full_name.strip()
    user.hashed_password = hash_password(payload.password)
    user.is_active = True
    user.is_verified = user.is_verified or False

    if not existing:
        db.add(user)

    db.commit()
    db.refresh(user)

    token = _create_session(user, db, request)
    _set_auth_cookie(response, token)
    _log_action(
        db,
        "signup_email",
        user_id=user.id,
        request=request,
    )

    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRE_DAYS * 86400,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Email + password login",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(
        User.email == payload.email,
        User.is_active == True,
    ).first()

    if not user or not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not verify_password(payload.password,
                           user.hashed_password):
        _log_action(db, "login_failed",
                    metadata={"email": payload.email},
                    request=request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = _create_session(user, db, request)
    _set_auth_cookie(response, token)
    _log_action(db, "login_success",
                user_id=user.id, request=request)

    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRE_DAYS * 86400,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    summary="Invalidate current session",
)
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        token_hash = hash_token(token)
        db.query(UserSession).filter(
            UserSession.token_hash == token_hash
        ).update({"is_active": False})
        db.commit()

    _clear_auth_cookie(response)

    _log_action(db, "logout",
                user_id=current_user.id, request=request)
    return {"status": "logged_out"}


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
):
    return MeResponse(
        id=str(current_user.id),
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        plan=current_user.plan,
        scan_count=current_user.scan_count,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at.isoformat(),
        last_login=current_user.last_login.isoformat()
                   if current_user.last_login else None,
    )


@router.post(
    "/password/check",
    response_model=PasswordStrengthResponse,
    summary="Check password strength",
)
async def check_password(payload: dict):
    password = payload.get("password", "")
    result = validate_password_strength(password)
    return PasswordStrengthResponse(**result)


@router.delete(
    "/sessions",
    summary="Revoke all sessions",
)
async def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id
    ).update({"is_active": False})
    db.commit()
    return {"status": "all_sessions_revoked"}
