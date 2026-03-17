"""
schemas/super_admin_schema.py — Pydantic models for super admin endpoints.

Key rules:
  - CreateAccountRequest enforces role is only 'admin' or 'super_admin'
    (users self-register — super_admin never creates user-role accounts)
  - DeleteAccountRequest takes target_user_id in body — never in path params
  - All responses never include password hashes
  - BulkCreateResponse gives a detailed per-row error report
"""

from typing import Literal, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class CreateAccountRequest(BaseModel):
    """
    Body for POST /super-admin/create-account.
    Creates a single admin or super_admin account.
    """
    first_name: str      = Field(..., min_length=1, max_length=100)
    last_name:  str      = Field(..., min_length=1, max_length=100)
    email:      EmailStr = Field(...)
    password:   str      = Field(..., min_length=8)
    role:       Literal["admin", "super_admin"] = Field(
        ...,
        description="Must be 'admin' or 'super_admin'. Users self-register via /auth/signup."
    )

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("first_name", "last_name", mode="before")
    @classmethod
    def strip_names(cls, v: str) -> str:
        return v.strip()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class DeleteAccountRequest(BaseModel):
    """
    Body for POST /super-admin/delete-account.
    target_user_id is in the body — no path params anywhere in this app.
    """
    target_user_id: str = Field(
        ...,
        description="UUID of the user to soft-delete"
    )


class ListUsersRequest(BaseModel):
    """
    Body for POST /super-admin/users.
    Optional filters — all default to None (no filter applied).
    """
    role:            Optional[Literal["admin", "super_admin", "user"]] = Field(
        None, description="Filter by role"
    )
    include_deleted: bool = Field(
        False, description="Include soft-deleted accounts in results"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────────────────────────────────────

class CreatedUserResponse(BaseModel):
    """Safe user object — password never included."""
    id:         str
    first_name: str
    last_name:  str
    email:      str
    role:       str
    created_at: str


class CreateAccountResponse(BaseModel):
    message: str
    user:    CreatedUserResponse


class BulkRowError(BaseModel):
    """Per-row error detail for bulk create response."""
    row_number: int
    errors:     list[str]
    raw_data:   dict


class BulkCreateResponse(BaseModel):
    message:       str
    total_rows:    int
    success_count: int
    failed_count:  int
    created_users: list[CreatedUserResponse]
    errors:        list[BulkRowError]


class DeleteAccountResponse(BaseModel):
    message:    str
    deleted_id: str


class UserListItem(BaseModel):
    id:         str
    first_name: str
    last_name:  str
    email:      str
    role:       str
    deleted:    bool
    created_at: str


class ListUsersResponse(BaseModel):
    message: str
    count:   int
    users:   list[UserListItem]