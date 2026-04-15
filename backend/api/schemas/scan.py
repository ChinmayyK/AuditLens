from pydantic import BaseModel, field_validator, HttpUrl
from typing import Optional
import re


BLOCKED_PRIVATE_PATTERNS = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"^192\.168\.",
    r"^127\.",
    r"^0\.",
    r"^localhost",
    r"^::1",
    r"^169\.254\.",
    r"^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.",
]


def is_private_ip(url: str) -> bool:
    for pattern in BLOCKED_PRIVATE_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


class UrlScanRequest(BaseModel):
    target_url: str
    intensity: str = "standard"
    ownership_confirmed: bool = False
    estimated_asset_value: Optional[int] = None

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                "URL must start with http:// or https://"
            )
        if is_private_ip(v):
            raise ValueError(
                "Private or local IP addresses are not allowed"
            )
        return v

    @field_validator("intensity")
    @classmethod
    def validate_intensity(cls, v):
        allowed = ["quick", "standard", "deep", "aggressive"]
        if v not in allowed:
            raise ValueError(
                f"Intensity must be one of: {allowed}"
            )
        return v

    @field_validator("ownership_confirmed")
    @classmethod
    def must_confirm(cls, v):
        if not v:
            raise ValueError(
                "You must confirm ownership or authorization"
            )
        return v


class GitHubScanRequest(BaseModel):
    repo_url: str
    ownership_confirmed: bool = False
    estimated_asset_value: Optional[int] = None

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v):
        v = v.strip()
        if "github.com" not in v:
            raise ValueError(
                "Only GitHub repositories are supported"
            )
        if v.endswith("/"):
            v = v[:-1]
        # Must be github.com/owner/repo format
        parts = v.replace("https://", "").replace(
            "http://", ""
        ).split("/")
        if len(parts) < 3:
            raise ValueError(
                "URL must be: github.com/owner/repo"
            )
        return v

    @field_validator("ownership_confirmed")
    @classmethod
    def must_confirm(cls, v):
        if not v:
            raise ValueError(
                "You must confirm ownership or authorization"
            )
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    scan_type: str
    ide_session_id: Optional[str] = None


class ScanDetailResponse(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    intensity: str
    risk_score: Optional[int]
    risk_grade: Optional[str]
    progress_pct: int
    current_phase: Optional[str]
    error_message: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[int]
    open_ports: Optional[list]
    subdomains: Optional[list]
    tech_stack: Optional[dict]
    os_guess: Optional[str]
    cdn_detected: Optional[bool]
    waf_detected: Optional[bool]
    waf_name: Optional[str]
    summary: Optional[dict]
