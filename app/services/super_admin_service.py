"""
services/super_admin_service.py — DB logic for super admin operations.

Enforced rules:
  - super_admin cannot delete themselves
  - Email uniqueness checked before every insert (single and bulk)
  - Bulk insert: each row is attempted individually so one failure
    does not block others — per-row error report returned
  - Soft delete sets deleted=TRUE — never a hard DELETE
  - updated_at on delete is handled by the DB trigger automatically
  - List users supports role filter and include_deleted flag
"""

from typing import Optional

from app.database import get_connection
from app.utils.password import hash_password
from app.utils.xlsx_parser import ParsedRow, XLSXParseResult


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _format_user(row) -> dict:
    """Convert asyncpg Record to safe dict. Password excluded always."""
    return {
        "id":         str(row["id"]),
        "first_name": row["first_name"],
        "last_name":  row["last_name"],
        "email":      row["email"],
        "role":       row["role"],
        "created_at": row["created_at"].isoformat(),
    }


def _format_user_with_deleted(row) -> dict:
    """Extended format that includes deleted flag (for list endpoint)."""
    return {
        "id":         str(row["id"]),
        "first_name": row["first_name"],
        "last_name":  row["last_name"],
        "email":      row["email"],
        "role":       row["role"],
        "deleted":    row["deleted"],
        "created_at": row["created_at"].isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Create single account
# ─────────────────────────────────────────────────────────────────────────────

async def create_account(
    first_name: str,
    last_name:  str,
    email:      str,
    password:   str,
    role:       str,
) -> dict:
    """
    Create a single admin or super_admin account.

    Raises:
        ValueError if the email is already registered (active or deleted).

    Returns:
        Safe user dict (no password).
    """
    async with get_connection() as conn:

        # Check email uniqueness — block even deleted accounts
        # (prevents silently re-creating a soft-deleted account)
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1",
            email,
        )
        if existing:
            raise ValueError(f"An account with email '{email}' already exists")

        hashed = hash_password(password)

        row = await conn.fetchrow(
            """
            INSERT INTO users (first_name, last_name, email, password, role)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, first_name, last_name, email, role, created_at
            """,
            first_name,
            last_name,
            email,
            hashed,
            role,
        )

    return _format_user(row)


# ─────────────────────────────────────────────────────────────────────────────
# Bulk create from XLSX parse result
# ─────────────────────────────────────────────────────────────────────────────

async def bulk_create_accounts(parse_result: XLSXParseResult) -> dict:
    """
    Attempt to insert all valid rows from the XLSX parse result.

    Each valid row is attempted individually inside the same connection.
    If a row's email is already taken, it is added to db_errors — the
    remaining rows continue to be processed (no rollback on partial failure).

    Args:
        parse_result: Result from xlsx_parser.parse_xlsx()

    Returns:
        Dict with:
          created_users  : list of successfully inserted user dicts
          db_errors      : rows that passed XLSX validation but failed DB insert
          parse_errors   : rows that failed XLSX validation (from parse_result)
    """
    created_users = []
    db_errors     = []

    async with get_connection() as conn:
        for parsed_row in parse_result.valid_rows:
            try:
                # Check email uniqueness per row
                existing = await conn.fetchrow(
                    "SELECT id FROM users WHERE email = $1",
                    parsed_row.email,
                )
                if existing:
                    db_errors.append({
                        "email":  parsed_row.email,
                        "errors": [f"Email '{parsed_row.email}' is already registered"],
                    })
                    continue

                hashed = hash_password(parsed_row.password)

                row = await conn.fetchrow(
                    """
                    INSERT INTO users (first_name, last_name, email, password, role)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id, first_name, last_name, email, role, created_at
                    """,
                    parsed_row.first_name,
                    parsed_row.last_name,
                    parsed_row.email,
                    hashed,
                    parsed_row.role,
                )
                created_users.append(_format_user(row))

            except Exception as e:
                # Catch any unexpected DB error for this row
                db_errors.append({
                    "email":  parsed_row.email,
                    "errors": [f"Database error: {str(e)}"],
                })

    return {
        "created_users": created_users,
        "db_errors":     db_errors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Soft delete
# ─────────────────────────────────────────────────────────────────────────────

async def soft_delete_account(
    target_user_id: str,
    requesting_user_id: str,
) -> dict:
    """
    Soft-delete a user by setting deleted=TRUE.

    Rules:
      - Super admin cannot delete themselves
      - Target must exist and not already be deleted
      - updated_at is updated by DB trigger automatically

    Args:
        target_user_id      : UUID of the account to delete
        requesting_user_id  : UUID of the super_admin making the request
                              (from JWT cookie — used for self-delete check)

    Raises:
        ValueError with specific message for each failure case.

    Returns:
        Dict with deleted user's id.
    """
    # Self-delete check — super_admin cannot delete themselves
    if target_user_id == requesting_user_id:
        raise ValueError("You cannot delete your own account")

    async with get_connection() as conn:

        # Fetch target — check existence and current deleted status
        target = await conn.fetchrow(
            "SELECT id, deleted FROM users WHERE id = $1",
            target_user_id,
        )

        if not target:
            raise ValueError(f"No user found with id '{target_user_id}'")

        if target["deleted"]:
            raise ValueError("This account is already deleted")

        # Perform soft delete — trigger updates updated_at automatically
        await conn.execute(
            "UPDATE users SET deleted = TRUE WHERE id = $1",
            target_user_id,
        )

    return {"deleted_id": target_user_id}


# ─────────────────────────────────────────────────────────────────────────────
# List users
# ─────────────────────────────────────────────────────────────────────────────

async def list_users(
    role: Optional[str],
    include_deleted: bool,
) -> list[dict]:
    """
    Fetch all users with optional filters.

    Args:
        role            : Filter by role, or None for all roles
        include_deleted : If False, only return non-deleted users

    Returns:
        List of user dicts (includes deleted flag, excludes password).
    """
    # Build dynamic WHERE clause
    conditions = []
    values     = []
    idx        = 1

    if not include_deleted:
        conditions.append(f"deleted = FALSE")

    if role is not None:
        conditions.append(f"role = ${idx}::user_role")
        values.append(role)
        idx += 1

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    query = f"""
        SELECT id, first_name, last_name, email, role, deleted, created_at
        FROM   users
        {where_clause}
        ORDER BY created_at DESC
    """

    async with get_connection() as conn:
        rows = await conn.fetch(query, *values)

    return [_format_user_with_deleted(row) for row in rows]