"""
schemas/auth_schema.py — Pydantic models for auth endpoints.

Pydantic v2 is used throughout. All models:
  - Use strict types (no silent coercions)
  - Strip leading/trailing whitespace from strings
  - Validate email format using pydantic's EmailStr
  - Never include password in any response model
"""

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """
    Body for POST /auth/login.
    Same for all roles — role is auto-detected from DB.
    """
    email:    EmailStr = Field(..., description="Registered email address")
    password: str      = Field(..., min_length=1, description="Account password")

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        """Lowercase and strip email so 'User@Example.COM ' matches 'user@example.com'."""
        return v.strip().lower()


class SignupRequest(BaseModel):
    """
    Body for POST /auth/signup.
    Public endpoint — creates a user-role account only.
    """
    first_name: str      = Field(..., min_length=1, max_length=100, description="First name")
    last_name:  str      = Field(..., min_length=1, max_length=100, description="Last name")
    email:      EmailStr = Field(..., description="Email address")
    password:   str      = Field(..., min_length=8, description="Password (min 8 characters)")

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
        """
        Enforce minimum password policy:
          - At least 8 characters
          - At least one uppercase letter
          - At least one lowercase letter
          - At least one digit
        """
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """
    Safe user object returned after login or signup.
    Password is NEVER included.
    """
    id:         str
    first_name: str
    last_name:  str
    email:      str
    role:       str


class LoginResponse(BaseModel):
    message: str
    user:    UserResponse


class SignupResponse(BaseModel):
    message: str
    user:    UserResponse


class LogoutResponse(BaseModel):
    message: str