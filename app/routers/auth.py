"""
routers/auth.py — Authentication endpoints.

Routes:
  POST /auth/login   — All roles (super_admin, admin, user). Sets HttpOnly JWT cookie.
  POST /auth/signup  — Public. Creates user-role accounts only.
  POST /auth/logout  — Clears the JWT cookie.

Design decisions:
  - No Bearer tokens. Cookie only.
  - One login route for all roles — role auto-detected from DB.
  - Deleted accounts get a specific error message with restore instructions.
  - All errors are returned as JSON with a consistent { "detail": "..." } shape
    (FastAPI's default HTTPException format).
"""

from fastapi import APIRouter, HTTPException, Response, status

from app.schemas.auth_schema import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    SignupRequest,
    SignupResponse,
    UserResponse,
)
from app.services.auth_service import authenticate_user, create_user
from app.utils.jwt_handler import clear_auth_cookie, create_access_token, set_auth_cookie

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# POST /auth/login
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Login — all roles",
    description=(
        "Authenticate with email and password. "
        "Works for super_admin, admin, and user roles. "
        "Returns user details and sets an HttpOnly JWT cookie."
    ),
)
async def login(body: LoginRequest, response: Response):
    """
    1. Validate credentials against DB
    2. Reject deleted accounts with a clear message
    3. Create JWT with user_id + role as claims
    4. Set JWT in HttpOnly cookie
    5. Return safe user object in response body
    """
    try:
        user = await authenticate_user(
            email=body.email,
            plain_password=body.password,
        )
    except ValueError as e:
        # authenticate_user raises ValueError for:
        #   - Email not found (generic message to prevent enumeration)
        #   - Account deleted
        #   - Wrong password (generic message)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    # Create token with minimal claims — sub (UUID) + role only
    token = create_access_token(user_id=user["id"], role=user["role"])

    # Attach token as HttpOnly cookie — JS cannot read this
    set_auth_cookie(response, token)

    return LoginResponse(
        message="Login successful",
        user=UserResponse(**user),
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /auth/signup
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Signup — users only",
    description=(
        "Public endpoint to create a new user-role account. "
        "Admins and super_admins are created by super_admin only — "
        "they cannot self-register here."
    ),
)
async def signup(body: SignupRequest, response: Response):
    """
    1. Validate input (password strength enforced in schema)
    2. Check email uniqueness
    3. Hash password with bcrypt
    4. Insert user with role='user'
    5. Auto-login after signup — set JWT cookie immediately
    6. Return safe user object
    """
    try:
        user = await create_user(
            first_name=body.first_name,
            last_name=body.last_name,
            email=body.email,
            plain_password=body.password,
        )
    except ValueError as e:
        # create_user raises ValueError for duplicate email
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )

    # Auto-login: set cookie immediately after successful registration
    token = create_access_token(user_id=user["id"], role=user["role"])
    set_auth_cookie(response, token)

    return SignupResponse(
        message="Account created successfully",
        user=UserResponse(**user),
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /auth/logout
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout — all roles",
    description="Clears the HttpOnly JWT cookie. Works for all roles.",
)
async def logout(response: Response):
    """
    Clears the JWT cookie by setting max_age=0.
    No DB call needed — stateless JWT logout is cookie deletion.

    Note: The token itself is still technically valid until expiry
    if someone copied it. For production systems requiring instant
    invalidation, a token blacklist (Redis) can be added later.
    """
    clear_auth_cookie(response)
    return LogoutResponse(message="Logged out successfully")