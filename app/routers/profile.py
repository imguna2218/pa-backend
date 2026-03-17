"""
routers/profile.py — Profile endpoints for all authenticated roles.

Routes:
  GET /profile/me      — Fetch own profile (super_admin, admin, user)
  PUT /profile/update  — Edit own profile (super_admin, admin, user)

Security:
  - Both routes are protected by require_authenticated.
  - The user_id used for all DB operations comes from current_user
    (resolved from JWT cookie by get_current_user) — NEVER from the
    request body. This makes it structurally impossible for a user
    to read or modify someone else's profile through these endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.middleware.auth_middleware import require_authenticated
from app.dependencies import CurrentUser
from app.schemas.profile_schema import (
    GetProfileResponse,
    ProfileResponse,
    UpdateProfileRequest,
    UpdateProfileResponse,
)
from app.services.profile_service import get_profile, update_profile

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# GET /profile/me
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=GetProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get own profile",
    description=(
        "Returns the full profile of the currently authenticated user. "
        "Available to super_admin, admin, and user roles."
    ),
)
async def get_my_profile(
    current_user: CurrentUser = Depends(require_authenticated),
):
    """
    Fetch the authenticated user's own profile from the DB.
    user_id is taken from the JWT cookie — never from the request body.
    """
    try:
        user = await get_profile(user_id=current_user.id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return GetProfileResponse(
        message="Profile fetched successfully",
        user=ProfileResponse(**user),
    )


# ─────────────────────────────────────────────────────────────────────────────
# PUT /profile/update
# ─────────────────────────────────────────────────────────────────────────────

@router.put(
    "/update",
    response_model=UpdateProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Update own profile",
    description=(
        "Update any combination of: first_name, last_name, email, password. "
        "Send only the fields you want to change — untouched fields stay as-is. "
        "Password change requires both current_password and new_password. "
        "Available to super_admin, admin, and user roles."
    ),
)
async def update_my_profile(
    body: UpdateProfileRequest,
    current_user: CurrentUser = Depends(require_authenticated),
):
    """
    Partially update the authenticated user's own profile.

    user_id is sourced from the JWT cookie via current_user — never from body.
    Only fields present in the request body are updated in the DB.
    """
    try:
        user = await update_profile(
            user_id=current_user.id,
            first_name=body.first_name,
            last_name=body.last_name,
            email=body.email,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    except ValueError as e:
        # Map specific error messages to appropriate status codes
        error_msg = str(e)

        if "already in use" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_msg,
            )
        if "incorrect" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    return UpdateProfileResponse(
        message="Profile updated successfully",
        user=ProfileResponse(**user),
    )