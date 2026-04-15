from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from uuid import UUID


class GoogleVerifyRequest(BaseModel):
    credential: str


class CompleteSignupRequest(BaseModel):
    google_id: str
    password: str
    confirm_password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str

    @field_validator("full_name")
    @classmethod
    def full_name_required(cls, v):
        if not v or not v.strip():
            raise ValueError("Full name is required")
        return v.strip()

    @field_validator("password")
    @classmethod
    def signup_password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class GoogleLoginRequest(BaseModel):
    credential: str


class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: str
    avatar_url: Optional[str]
    plan: str
    scan_count: int
    is_verified: bool

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class GoogleVerifyResponse(BaseModel):
    status: str
    google_id: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    requires_password: bool = False
    access_token: Optional[str] = None
    user: Optional[UserResponse] = None


class PasswordStrengthResponse(BaseModel):
    valid: bool
    score: int
    strength: str
    errors: list[str]


class MeResponse(BaseModel):
    id: str
    email: str
    full_name: str
    avatar_url: Optional[str]
    plan: str
    scan_count: int
    is_verified: bool
    created_at: str
    last_login: Optional[str]
