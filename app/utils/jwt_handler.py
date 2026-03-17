"""
utils/jwt_handler.py — JWT creation, decoding, and cookie helpers.

Token strategy:
  - Single access token (no refresh token)
  - Delivered via HttpOnly cookie (never exposed to JS)
  - HS256 signed with JWT_SECRET from .env
  - Expires in JWT_EXPIRE_MINUTES (default 60 min)

Token payload (claims):
  - sub  : user UUID (subject)
  - role : user_role string ("super_admin" | "admin" | "user")
  - exp  : expiry timestamp (set by jose automatically)
  - iat  : issued-at timestamp

We do NOT put sensitive data (email, name, password) in the token.
The sub (UUID) is all we need to look up the user from the DB.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Response
from jose import JWTError, jwt

from app.config import (
    COOKIE_MAX_AGE,
    COOKIE_NAME,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    JWT_ALGORITHM,
    JWT_EXPIRE_MINUTES,
    JWT_SECRET,
)


# ─────────────────────────────────────────────────────────────────────────────
# Token creation
# ─────────────────────────────────────────────────────────────────────────────

def create_access_token(user_id: str, role: str) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id : UUID string of the authenticated user (becomes "sub" claim).
        role    : Role string — "super_admin" | "admin" | "user".

    Returns:
        Signed JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=JWT_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ─────────────────────────────────────────────────────────────────────────────
# Token decoding
# ─────────────────────────────────────────────────────────────────────────────

class TokenPayload:
    """Typed container for decoded JWT claims."""

    def __init__(self, user_id: str, role: str) -> None:
        self.user_id = user_id
        self.role = role


def decode_access_token(token: str) -> Optional[TokenPayload]:
    """
    Decode and validate a JWT token string.

    Validates:
      - Signature (using JWT_SECRET)
      - Expiry (jose raises ExpiredSignatureError automatically)
      - Presence of required claims (sub, role)

    Args:
        token: Raw JWT string (extracted from cookie).

    Returns:
        TokenPayload with user_id and role if valid.
        None if token is expired, tampered, malformed, or missing claims.

    Never raises — always returns None on any failure so the caller
    can cleanly return a 401 without unhandled exceptions.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        user_id: str = payload.get("sub")
        role: str = payload.get("role")

        # Both claims are mandatory — reject token if either is absent
        if not user_id or not role:
            return None

        return TokenPayload(user_id=user_id, role=role)

    except JWTError:
        # Covers: ExpiredSignatureError, JWTClaimsError, DecodeError, etc.
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Cookie helpers
# ─────────────────────────────────────────────────────────────────────────────

def set_auth_cookie(response: Response, token: str) -> None:
    """
    Attach the JWT as an HttpOnly cookie to a FastAPI response.

    Cookie flags:
      - httponly=True   : JS cannot read this cookie (XSS protection)
      - secure=True     : Only sent over HTTPS (set via .env for production)
      - samesite="lax"  : Sent on same-site navigations, blocks CSRF from
                          cross-site POSTs while allowing normal navigation
      - max_age         : Matches JWT expiry so cookie and token expire together

    Args:
        response : FastAPI Response object to attach the cookie to.
        token    : Signed JWT string to store in the cookie.
    """
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=COOKIE_MAX_AGE,
    )


def clear_auth_cookie(response: Response) -> None:
    """
    Clear the auth cookie on logout.

    Sets max_age=0 which instructs the browser to immediately delete
    the cookie. Also explicitly deletes by key as a belt-and-suspenders
    measure across different browser implementations.

    Args:
        response: FastAPI Response object to clear the cookie from.
    """
    response.delete_cookie(
        key=COOKIE_NAME,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )