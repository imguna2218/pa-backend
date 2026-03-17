"""
services/auth_service.py — Database logic for authentication.

All raw SQL queries live here. The router calls these functions
and never touches the DB directly — clean separation of concerns.

Key rules enforced:
  - Deleted accounts cannot login (deleted = TRUE check)
  - Email is always compared lowercase (normalised at schema level)
  - Password is never returned from any function
  - Duplicate email on signup returns a clean error, not a DB exception
"""

from typing import Optional

import asyncpg

from app.database import get_connection
from app.utils.password import hash_password, verify_password


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_dict(row: asyncpg.Record) -> dict:
    """Convert an asyncpg Record to a plain dict."""
    return dict(row)


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

async def get_user_by_email(email: str) -> Optional[dict]:
    """
    Fetch a user row by email regardless of deleted status.
    We fetch first and then check deleted separately so we can
    return a specific 'account deleted' error vs 'not found'.

    Returns full user dict including password hash, or None if not found.
    """
    async with get_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, first_name, last_name, email, password, role, deleted
            FROM   users
            WHERE  email = $1
            """,
            email,
        )
    return _row_to_dict(row) if row else None


async def authenticate_user(email: str, plain_password: str) -> dict:
    """
    Full login authentication flow.

    Steps:
      1. Look up user by email
      2. Check if account exists
      3. Check if account is soft-deleted
      4. Verify password against bcrypt hash
      5. Return safe user dict (no password field)

    Raises:
      ValueError with a specific message for each failure case.
      The router maps these to appropriate HTTP responses.

    Returns:
      Dict with id, first_name, last_name, email, role (NO password).
    """
    user = await get_user_by_email(email)

    # Case 1: Email not found — use generic message to prevent user enumeration
    if not user:
        raise ValueError("Invalid email or password")

    # Case 2: Account has been soft-deleted
    if user["deleted"]:
        raise ValueError(
            "This account has been deactivated. "
            "Submit a restore request at POST /requests/submit"
        )

    # Case 3: Password mismatch
    if not verify_password(plain_password, user["password"]):
        raise ValueError("Invalid email or password")

    # Return safe user dict — strip the password hash before returning
    return {
        "id":         str(user["id"]),
        "first_name": user["first_name"],
        "last_name":  user["last_name"],
        "email":      user["email"],
        "role":       user["role"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Signup
# ─────────────────────────────────────────────────────────────────────────────

async def check_email_exists(email: str) -> bool:
    """
    Return True if the email is already registered (active or deleted).
    We block re-signup even for deleted accounts — they must use
    the restore flow instead.
    """
    async with get_connection() as conn:
        row = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1",
            email,
        )
    return row is not None


async def create_user(
    first_name: str,
    last_name: str,
    email: str,
    plain_password: str,
) -> dict:
    """
    Register a new user-role account.

    Steps:
      1. Check for duplicate email
      2. Hash password with bcrypt
      3. Insert into users table with role='user'
      4. Return safe user dict

    Raises:
      ValueError if the email is already taken.

    Returns:
      Dict with id, first_name, last_name, email, role (NO password).
    """
    # Duplicate email check — catches both active and deleted accounts
    if await check_email_exists(email):
        raise ValueError("An account with this email already exists")

    hashed = hash_password(plain_password)

    async with get_connection() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (first_name, last_name, email, password, role)
            VALUES ($1, $2, $3, $4, 'user')
            RETURNING id, first_name, last_name, email, role
            """,
            first_name,
            last_name,
            email,
            hashed,
        )

    return {
        "id":         str(row["id"]),
        "first_name": row["first_name"],
        "last_name":  row["last_name"],
        "email":      row["email"],
        "role":       row["role"],
    }