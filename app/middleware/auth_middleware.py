"""
middleware/auth_middleware.py — RBAC dependency factories.

These are FastAPI dependencies that wrap get_current_user and add
a role check on top. Import and use them directly in route definitions.

Role hierarchy (highest to lowest):
    super_admin  →  can do everything
    admin        →  subset of super_admin abilities
    user         →  basic authenticated access

Usage in routes:
    # Only super_admin can access:
    @router.post("/create-account")
    async def create_account(current_user: CurrentUser = Depends(require_super_admin)):
        ...

    # super_admin OR admin can access:
    @router.get("/dashboard")
    async def dashboard(current_user: CurrentUser = Depends(require_admin_or_above)):
        ...

    # Any authenticated user (super_admin, admin, user):
    @router.get("/me")
    async def get_me(current_user: CurrentUser = Depends(require_authenticated)):
        ...

Design:
    Each factory is a plain async function (not a class) so FastAPI
    can resolve the Depends() chain cleanly. They all call get_current_user
    first — so the full auth flow (cookie → JWT → DB → deleted check)
    always runs before the role check.
"""

from fastapi import Depends, HTTPException, status

from app.dependencies import CurrentUser, get_current_user

# ─────────────────────────────────────────────────────────────────────────────
# Role constants — single source of truth, avoids magic strings
# ─────────────────────────────────────────────────────────────────────────────

ROLE_SUPER_ADMIN = "super_admin"
ROLE_ADMIN       = "admin"
ROLE_USER        = "user"

# Ordered set for hierarchy checks
_ADMIN_AND_ABOVE = {ROLE_SUPER_ADMIN, ROLE_ADMIN}
_ALL_ROLES       = {ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER}


# ─────────────────────────────────────────────────────────────────────────────
# Dependency: super_admin only
# ─────────────────────────────────────────────────────────────────────────────

async def require_super_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Allows access only to super_admin role.

    Used for:
      - Creating / deleting admin and super_admin accounts
      - Bulk XLSX upload
      - Viewing and actioning the request box

    Raises 403 if the authenticated user is admin or user.
    """
    if current_user.role != ROLE_SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Super admin privileges required.",
        )
    return current_user


# ─────────────────────────────────────────────────────────────────────────────
# Dependency: admin or above (super_admin + admin)
# ─────────────────────────────────────────────────────────────────────────────

async def require_admin_or_above(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Allows access to super_admin and admin roles.

    Raises 403 if the authenticated user is a plain user.
    """
    if current_user.role not in _ADMIN_AND_ABOVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Admin privileges required.",
        )
    return current_user


# ─────────────────────────────────────────────────────────────────────────────
# Dependency: any authenticated user
# ─────────────────────────────────────────────────────────────────────────────

async def require_authenticated(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Allows any authenticated, non-deleted user (super_admin, admin, user).

    This is the base protection layer — use it for routes like:
      - GET /profile/me
      - PUT /profile/update

    The route handler is responsible for any further ownership checks
    (e.g. ensuring a user can only edit their own profile).
    """
    # get_current_user already handles all rejection cases.
    # This function exists for explicitness and Swagger tag grouping.
    return current_user