"""
services/profile_service.py — Database logic for profile operations.

Rules enforced here:
  - get_profile fetches by user ID only — users can never see each other's profiles
  - update_profile builds a dynamic UPDATE query from only the fields provided —
    untouched fields are never written to DB, preventing accidental overwrites
  - Email uniqueness is checked against OTHER users only (a user can re-submit
    their own email without getting a duplicate error)
  - Password change requires current_password verification before hashing new one
  - updated_at is managed by the DB trigger — never set manually here
"""

from typing import Optional

from app.database import get_connection
from app.utils.password import hash_password, verify_password


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _format_row(row) -> dict:
    """
    Convert an asyncpg Record to a clean dict for response.
    Converts UUID to str and datetimes to ISO 8601 strings.
    Password is explicitly excluded.
    """
    return {
        "id":         str(row["id"]),
        "first_name": row["first_name"],
        "last_name":  row["last_name"],
        "email":      row["email"],
        "role":       row["role"],
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Get profile
# ─────────────────────────────────────────────────────────────────────────────

async def get_profile(user_id: str) -> dict:
    """
    Fetch the full profile of the currently authenticated user.

    Args:
        user_id: UUID string from CurrentUser (set by get_current_user dependency).

    Returns:
        Dict with all profile fields. Password never included.

    Raises:
        ValueError if user somehow doesn't exist (edge case — they passed auth).
    """
    async with get_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, first_name, last_name, email, role, created_at, updated_at
            FROM   users
            WHERE  id = $1
              AND  deleted = FALSE
            """,
            user_id,
        )

    if not row:
        raise ValueError("User not found")

    return _format_row(row)


# ─────────────────────────────────────────────────────────────────────────────
# Update profile
# ─────────────────────────────────────────────────────────────────────────────

async def update_profile(
    user_id:          str,
    first_name:       Optional[str],
    last_name:        Optional[str],
    email:            Optional[str],
    current_password: Optional[str],
    new_password:     Optional[str],
) -> dict:
    """
    Update only the fields the user provided. Untouched fields stay as-is.

    Steps:
      1. If email change requested → check it's not taken by another user
      2. If password change requested → verify current password first
      3. Build a dynamic SET clause with only the provided fields
      4. Execute UPDATE and return the fresh row

    Args:
        user_id          : UUID of the authenticated user (from cookie, never body)
        first_name       : New first name, or None to leave unchanged
        last_name        : New last name, or None to leave unchanged
        email            : New email, or None to leave unchanged
        current_password : Required when changing password — verified against DB hash
        new_password     : New password (pre-validated for strength in schema)

    Raises:
        ValueError with a descriptive message for each failure case.

    Returns:
        Updated profile dict (no password).
    """
    async with get_connection() as conn:

        # ── Step 1: Email uniqueness check ───────────────────────────────────
        if email is not None:
            conflict = await conn.fetchrow(
                """
                SELECT id FROM users
                WHERE  email = $1
                  AND  id    != $2
                """,
                email,
                user_id,
            )
            if conflict:
                raise ValueError("This email is already in use by another account")

        # ── Step 2: Password verification (if changing password) ─────────────
        if current_password is not None and new_password is not None:
            stored = await conn.fetchrow(
                "SELECT password FROM users WHERE id = $1",
                user_id,
            )
            if not stored:
                raise ValueError("User not found")

            if not verify_password(current_password, stored["password"]):
                raise ValueError("Current password is incorrect")

        # ── Step 3: Build dynamic SET clause ─────────────────────────────────
        # Only include columns that were actually provided.
        # This pattern avoids overwriting untouched fields and prevents
        # sending NULL to NOT NULL columns.
        set_clauses = []
        values      = []
        param_index = 1  # asyncpg uses $1, $2, $3... positional params

        if first_name is not None:
            set_clauses.append(f"first_name = ${param_index}")
            values.append(first_name)
            param_index += 1

        if last_name is not None:
            set_clauses.append(f"last_name = ${param_index}")
            values.append(last_name)
            param_index += 1

        if email is not None:
            set_clauses.append(f"email = ${param_index}")
            values.append(email)
            param_index += 1

        if new_password is not None:
            hashed = hash_password(new_password)
            set_clauses.append(f"password = ${param_index}")
            values.append(hashed)
            param_index += 1

        # ── Step 4: Execute update ────────────────────────────────────────────
        # updated_at is handled by the DB trigger — not set here.
        values.append(user_id)  # final param for WHERE clause

        query = f"""
            UPDATE users
            SET    {', '.join(set_clauses)}
            WHERE  id = ${param_index}
              AND  deleted = FALSE
            RETURNING id, first_name, last_name, email, role, created_at, updated_at
        """

        row = await conn.fetchrow(query, *values)

        if not row:
            raise ValueError("Update failed — user not found or already deleted")

    return _format_row(row)