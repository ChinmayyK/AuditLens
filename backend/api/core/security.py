import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

JWT_SECRET = os.getenv("JWT_SECRET", "changeme")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_DAYS = int(os.getenv("JWT_EXPIRE_DAYS", "7"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(
    user_id: str,
    email: str,
    plan: str = "free",
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.utcnow() + (
        expires_delta or timedelta(days=JWT_EXPIRE_DAYS)
    )
    payload = {
        "sub": user_id,
        "email": email,
        "plan": plan,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET,
                      algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET,
                          algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def validate_password_strength(password: str) -> dict:
    errors = []
    score = 0

    if len(password) < 8:
        errors.append("Minimum 8 characters")
    else:
        score += 1

    if not any(c.isdigit() for c in password):
        errors.append("At least one number")
    else:
        score += 1

    if not any(c.isupper() for c in password):
        errors.append("At least one uppercase letter")
    else:
        score += 1

    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        errors.append("At least one special character")
    else:
        score += 1

    if len(password) >= 16:
        score += 1

    strength = ["very_weak", "weak", "moderate",
                "strong", "very_strong"][min(score, 4)]

    return {
        "valid": len(errors) == 0,
        "score": score,
        "strength": strength,
        "errors": errors,
    }
