"""
dependencies.py — FastAPI dependency for authenticated user resolution.

How it works on every protected request:
  1. Extract JWT string from HttpOnly cookie
  2. Decode + validate the token (signature, expiry, required claims)
  3. Use the user_id (sub claim) to fetch the LIVE user record from DB
  4. Reject the request if the user has been soft-deleted since token was issued
  5. Return a CurrentUser object that routes can use directly

Why fetch from DB on every request instead of trusting the token claims?
  - If a super_admin soft-deletes a user, that user's token is still
    cryptographically valid until expiry. Without a DB check, they'd
    continue to have access for up to 60 minutes after deletion.
  - We fetch only id, role, deleted — a single indexed primary key lookup,
    so the performance cost is negligible.

Usage in a route:
    @router.get("/me")
    async def get_me(current_user: CurrentUser = Depends(get_current_user)):
        return current_user
"""

from fastapi import Cookie, Depends, HTTPException, status

from app.config import COOKIE_NAME
from app.database import get_connection
from app.utils.jwt_handler import decode_access_token


# ─────────────────────────────────────────────────────────────────────────────
# CurrentUser — typed container passed to every protected route
# ─────────────────────────────────────────────────────────────────────────────

class CurrentUser:
    """
    Represents the authenticated, active user making the request.
    Populated from the live DB record — not solely from the JWT claims.

    Attributes:
        id         : UUID string of the user
        first_name : User's first name
        last_name  : User's last name
        email      : User's email address
        role       : Role string — "super_admin" | "admin" | "user"
    """

    def __init__(self, id: str, first_name: str, last_name: str, email: str, role: str):
        self.id         = id
        self.first_name = first_name
        self.last_name  = last_name
        self.email      = email
        self.role       = role

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "first_name": self.first_name,
            "last_name":  self.last_name,
            "email":      self.email,
            "role":       self.role,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Cookie extractor
# ─────────────────────────────────────────────────────────────────────────────

def _extract_token(access_token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> str:
    """
    FastAPI dependency that reads the JWT from the HttpOnly cookie.

    Cookie name is driven by COOKIE_NAME in config (default: "access_token").
    Returns the raw token string, or raises 401 if cookie is absent.
    """
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please login first.",
        )
    return access_token


# ─────────────────────────────────────────────────────────────────────────────
# Core dependency
# ─────────────────────────────────────────────────────────────────────────────

async def get_current_user(token: str = Depends(_extract_token)) -> CurrentUser:
    """
    Core authentication dependency. Resolves the current user from
    the JWT cookie and a live DB lookup.

    Failure cases:
      - Cookie missing              → 401 (handled by _extract_token)
      - Token expired/tampered      → 401
      - Token missing required claims → 401
      - User not found in DB        → 401 (treat as invalid session)
      - User is soft-deleted        → 403 (account deactivated)

    Returns:
      CurrentUser instance for use in route handlers.
    """
    # Step 1: Decode and validate the JWT
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please login again.",
        )

    # Step 2: Fetch LIVE user record from DB using sub claim (UUID)
    async with get_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, first_name, last_name, email, role, deleted
            FROM   users
            WHERE  id = $1
            """,
            payload.user_id,
        )

    # Step 3: User must exist in DB
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid. User no longer exists.",
        )

    # Step 4: Reject soft-deleted users immediately
    # This ensures deletion takes effect on the next request even within
    # an active session — no waiting for token expiry.
    if row["deleted"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Your account has been deactivated. "
                "Submit a restore request at POST /requests/submit"
            ),
        )

    return CurrentUser(
        id=str(row["id"]),
        first_name=row["first_name"],
        last_name=row["last_name"],
        email=row["email"],
        role=row["role"],
    )