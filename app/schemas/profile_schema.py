"""
schemas/profile_schema.py — Pydantic models for profile endpoints.

Key design decisions:
  - All fields in UpdateProfileRequest are Optional — user sends only
    what they want to change, untouched fields are left as-is in DB.
  - At least one field must be provided in an update request.
  - Password change requires current_password for verification — a user
    cannot change their password without proving they know the old one.
  - Email is normalised to lowercase on input.
  - Password is NEVER included in any response model.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class UpdateProfileRequest(BaseModel):
    """
    Body for PUT /profile/update.

    All fields are optional — send only what needs changing.
    At least one field must be present (enforced by model_validator).

    Password change flow:
      - To change password, BOTH current_password AND new_password must be sent.
      - Sending only one of them is rejected.
      - current_password is verified against the bcrypt hash in DB before
        the new password is stored.
    """
    first_name:       Optional[str]      = Field(None, min_length=1, max_length=100)
    last_name:        Optional[str]      = Field(None, min_length=1, max_length=100)
    email:            Optional[EmailStr] = Field(None)
    current_password: Optional[str]      = Field(None, min_length=1, description="Required when changing password")
    new_password:     Optional[str]      = Field(None, min_length=8, description="New password (min 8 chars)")

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        if v is None:
            return v
        return v.strip().lower()

    @field_validator("first_name", "last_name", mode="before")
    @classmethod
    def strip_names(cls, v):
        if v is None:
            return v
        return v.strip()

    @field_validator("new_password")
    @classmethod
    def validate_new_password_strength(cls, v):
        """Same strength rules as signup."""
        if v is None:
            return v
        if not any(c.isupper() for c in v):
            raise ValueError("New password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("New password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("New password must contain at least one digit")
        return v

    @model_validator(mode="after")
    def validate_update_rules(self):
        """
        Cross-field validation rules:
          1. At least one field must be provided.
          2. current_password and new_password must come together — not one without the other.
        """
        all_fields = [
            self.first_name,
            self.last_name,
            self.email,
            self.current_password,
            self.new_password,
        ]
        # Rule 1: at least one field must be non-None
        if all(f is None for f in all_fields):
            raise ValueError("At least one field must be provided to update")

        # Rule 2: password change requires both current and new password together
        has_current = self.current_password is not None
        has_new     = self.new_password is not None
        if has_current != has_new:
            raise ValueError(
                "To change your password, provide both "
                "'current_password' and 'new_password' together"
            )

        return self


# ─────────────────────────────────────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────────────────────────────────────

class ProfileResponse(BaseModel):
    """Full profile object — password never included."""
    id:         str
    first_name: str
    last_name:  str
    email:      str
    role:       str
    created_at: str
    updated_at: str


class GetProfileResponse(BaseModel):
    message: str
    user:    ProfileResponse


class UpdateProfileResponse(BaseModel):
    message: str
    user:    ProfileResponse