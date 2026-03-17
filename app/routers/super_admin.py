"""
routers/super_admin.py — Super admin only endpoints.

All routes protected by require_super_admin dependency.
Any non-super_admin hitting these routes gets a 403 immediately.

Routes:
  POST /super-admin/create-account  → create single admin/super_admin
  POST /super-admin/bulk-create     → upload XLSX, per-row error report
  POST /super-admin/delete-account  → soft delete any user (not self)
  POST /super-admin/users           → list all users with optional filters

Design notes:
  - No path params anywhere — target_user_id always in request body
  - Bulk create uses multipart/form-data file upload (UploadFile)
  - Per-row error report on bulk create — valid rows inserted,
    failed rows reported with reasons — no full rollback
  - List uses POST (not GET) because filters go in body per project rules
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status

from app.dependencies import CurrentUser
from app.middleware.auth_middleware import require_super_admin
from app.schemas.super_admin_schema import (
    BulkCreateResponse,
    BulkRowError,
    CreateAccountRequest,
    CreateAccountResponse,
    CreatedUserResponse,
    DeleteAccountRequest,
    DeleteAccountResponse,
    ListUsersRequest,
    ListUsersResponse,
    UserListItem,
)
from app.services.super_admin_service import (
    bulk_create_accounts,
    create_account,
    list_users,
    soft_delete_account,
)
from app.utils.xlsx_parser import parse_xlsx

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# POST /super-admin/create-account
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/create-account",
    response_model=CreateAccountResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create single admin or super_admin account",
    description=(
        "Super admin only. Creates a single admin or super_admin account. "
        "Users self-register via /auth/signup — this endpoint is not for user-role creation. "
        "Password is NOT returned in the response."
    ),
)
async def create_single_account(
    body: CreateAccountRequest,
    current_user: CurrentUser = Depends(require_super_admin),
):
    try:
        user = await create_account(
            first_name=body.first_name,
            last_name=body.last_name,
            email=body.email,
            password=body.password,
            role=body.role,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )

    return CreateAccountResponse(
        message=f"{body.role.replace('_', ' ').title()} account created successfully",
        user=CreatedUserResponse(**user),
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /super-admin/bulk-create
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/bulk-create",
    response_model=BulkCreateResponse,
    status_code=status.HTTP_200_OK,
    summary="Bulk create admin/super_admin accounts via XLSX",
    description=(
        "Super admin only. Upload an XLSX file with columns: "
        "first_name, last_name, email, password, role. "
        "role must be 'admin' or 'super_admin'. "
        "Valid rows are inserted; failed rows are reported per-row. "
        "Returns a detailed success/failure report."
    ),
)
async def bulk_create(
    file: UploadFile = File(..., description="XLSX file with user data"),
    current_user: CurrentUser = Depends(require_super_admin),
):
    # ── Validate file type ────────────────────────────────────
    filename = file.filename or ""
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .xlsx files are accepted",
        )

    # ── Read file bytes ───────────────────────────────────────
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # ── Parse and validate XLSX ───────────────────────────────
    parse_result = parse_xlsx(file_bytes)

    # File-level errors (missing columns, unreadable file etc.)
    # These block all processing — return immediately
    if parse_result.has_file_errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message":     "XLSX file has structural errors",
                "file_errors": parse_result.file_errors,
            },
        )

    # ── Attempt DB inserts for all valid rows ─────────────────
    db_result = await bulk_create_accounts(parse_result)

    # ── Build per-row error list ──────────────────────────────
    # Combine XLSX validation errors + DB-level errors (duplicate emails etc.)
    all_errors: list[BulkRowError] = []

    # XLSX row errors (schema/format failures)
    for row_err in parse_result.row_errors:
        all_errors.append(BulkRowError(
            row_number=row_err.row_number,
            errors=row_err.errors,
            raw_data=row_err.raw_data,
        ))

    # DB errors (duplicate email, unexpected DB issue)
    for db_err in db_result["db_errors"]:
        all_errors.append(BulkRowError(
            row_number=0,  # Row number not tracked for DB-level errors
            errors=db_err["errors"],
            raw_data={"email": db_err["email"]},
        ))

    created_users = db_result["created_users"]
    success_count = len(created_users)
    failed_count  = len(all_errors)
    total_rows    = parse_result.total_rows

    # Build summary message
    if success_count == total_rows:
        message = f"All {success_count} accounts created successfully"
    elif success_count == 0:
        message = f"No accounts created. All {failed_count} rows failed"
    else:
        message = (
            f"{success_count} account(s) created, "
            f"{failed_count} row(s) failed"
        )

    return BulkCreateResponse(
        message=message,
        total_rows=total_rows,
        success_count=success_count,
        failed_count=failed_count,
        created_users=[CreatedUserResponse(**u) for u in created_users],
        errors=all_errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /super-admin/delete-account
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/delete-account",
    response_model=DeleteAccountResponse,
    status_code=status.HTTP_200_OK,
    summary="Soft delete any user account",
    description=(
        "Super admin only. Soft-deletes any account (admin, super_admin, or user). "
        "Sets deleted=TRUE — the record is never removed from the database. "
        "Super admin cannot delete their own account. "
        "target_user_id must be sent in the request body."
    ),
)
async def delete_account(
    body: DeleteAccountRequest,
    current_user: CurrentUser = Depends(require_super_admin),
):
    try:
        result = await soft_delete_account(
            target_user_id=body.target_user_id,
            requesting_user_id=current_user.id,
        )
    except ValueError as e:
        error_msg = str(e)

        # Self-delete attempt → 403
        if "own account" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=error_msg,
            )
        # Already deleted → 409
        if "already deleted" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_msg,
            )
        # Not found → 404
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error_msg,
        )

    return DeleteAccountResponse(
        message="Account successfully deactivated",
        deleted_id=result["deleted_id"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /super-admin/users
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/users",
    response_model=ListUsersResponse,
    status_code=status.HTTP_200_OK,
    summary="List all users",
    description=(
        "Super admin only. Returns all users with optional filters. "
        "Send an empty body {} to get all active users. "
        "Use role filter to narrow by 'admin', 'super_admin', or 'user'. "
        "Set include_deleted=true to include soft-deleted accounts."
    ),
)
async def get_users(
    body: ListUsersRequest,
    current_user: CurrentUser = Depends(require_super_admin),
):
    users = await list_users(
        role=body.role,
        include_deleted=body.include_deleted,
    )

    return ListUsersResponse(
        message=f"Found {len(users)} user(s)",
        count=len(users),
        users=[UserListItem(**u) for u in users],
    )