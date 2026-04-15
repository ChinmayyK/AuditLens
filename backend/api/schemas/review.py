"""
Pydantic schemas for the PR Review pipeline.

These are thin API-layer schemas for Dev 1's endpoints.
Dev 2's engine schemas (FindingInput, ReviewRequest, etc.)
live in review_engine/schemas/review.py.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class PRReviewRequest(BaseModel):
    """Input for POST /api/v1/review/github-pr."""
    repo_url: str = Field(
        ...,
        description="GitHub repository URL",
        json_schema_extra={
            "example": "https://github.com/octocat/hello-world"
        },
    )
    pr_number: int = Field(
        ...,
        gt=0,
        description="Pull request number",
    )

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if "github.com" not in v:
            raise ValueError(
                "Only GitHub repositories are supported"
            )
        return v


class PRReviewResponse(BaseModel):
    """Response from POST /api/v1/review/github-pr."""
    review_id: str
    status: str = "queued"
    message: str = ""
    pr_number: int
    repo: str


class PRMetadata(BaseModel):
    """Structured PR metadata from GitHub API."""
    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_branch: str
    head_branch: str
    title: str = ""
    author: str = ""
    html_url: str = ""
    clone_url: str = ""
