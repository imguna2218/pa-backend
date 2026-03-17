"""
utils/xlsx_parser.py — Parse and validate bulk user creation XLSX files.

Expected columns (case-insensitive, order-independent):
    first_name | last_name | email | password | role

Validation per row:
  - All 5 columns must be present and non-empty
  - email must be a valid email format
  - role must be exactly 'admin' or 'super_admin'
  - password must meet minimum strength requirements
    (min 8 chars, 1 uppercase, 1 lowercase, 1 digit)

Returns a structured result with valid rows and per-row errors
so the caller can insert valid rows and report failures.
"""

import io
import re
from dataclasses import dataclass, field
from typing import Optional

import openpyxl

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_COLUMNS = {"first_name", "last_name", "email", "password", "role"}
ALLOWED_ROLES    = {"admin", "super_admin"}
EMAIL_REGEX      = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRow:
    """A single valid, clean row ready for DB insertion."""
    first_name: str
    last_name:  str
    email:      str
    password:   str
    role:       str


@dataclass
class RowError:
    """A single row that failed validation."""
    row_number: int
    raw_data:   dict
    errors:     list[str]


@dataclass
class XLSXParseResult:
    """
    Full parse result returned to the service layer.

    valid_rows  : list of ParsedRow — safe to insert into DB
    row_errors  : list of RowError  — per-row failures with reasons
    file_errors : list of str       — file-level errors (missing columns etc.)
                  If file_errors is non-empty, valid_rows will be empty.
    """
    valid_rows:  list[ParsedRow] = field(default_factory=list)
    row_errors:  list[RowError]  = field(default_factory=list)
    file_errors: list[str]       = field(default_factory=list)

    @property
    def has_file_errors(self) -> bool:
        return len(self.file_errors) > 0

    @property
    def total_rows(self) -> int:
        return len(self.valid_rows) + len(self.row_errors)


# ─────────────────────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────────────────────

def _validate_password_strength(password: str) -> Optional[str]:
    """
    Returns an error string if password fails strength rules, else None.
    Same rules as signup schema.
    """
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit"
    return None


def _validate_row(row_data: dict, row_number: int) -> tuple[Optional[ParsedRow], Optional[RowError]]:
    """
    Validate a single row dict.

    Returns:
        (ParsedRow, None)  if row is valid
        (None, RowError)   if row has errors
    """
    errors = []

    # Extract and clean each field
    first_name = str(row_data.get("first_name", "") or "").strip()
    last_name  = str(row_data.get("last_name",  "") or "").strip()
    email      = str(row_data.get("email",      "") or "").strip().lower()
    password   = str(row_data.get("password",   "") or "").strip()
    role       = str(row_data.get("role",       "") or "").strip().lower()

    # Presence checks
    if not first_name:
        errors.append("first_name is required")
    if not last_name:
        errors.append("last_name is required")
    if not email:
        errors.append("email is required")
    elif not EMAIL_REGEX.match(email):
        errors.append(f"'{email}' is not a valid email address")
    if not password:
        errors.append("password is required")
    else:
        pw_error = _validate_password_strength(password)
        if pw_error:
            errors.append(pw_error)
    if not role:
        errors.append("role is required")
    elif role not in ALLOWED_ROLES:
        errors.append(f"role must be 'admin' or 'super_admin', got '{role}'")

    if errors:
        return None, RowError(
            row_number=row_number,
            raw_data={
                "first_name": first_name or row_data.get("first_name"),
                "last_name":  last_name  or row_data.get("last_name"),
                "email":      email      or row_data.get("email"),
                "role":       role       or row_data.get("role"),
                # Never include password in error output
            },
            errors=errors,
        )

    return ParsedRow(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=password,
        role=role,
    ), None


# ─────────────────────────────────────────────────────────────────────────────
# Main parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_xlsx(file_bytes: bytes) -> XLSXParseResult:
    """
    Parse an uploaded XLSX file and validate every row.

    Args:
        file_bytes: Raw bytes of the uploaded .xlsx file.

    Returns:
        XLSXParseResult with valid_rows, row_errors, and file_errors.

    Never raises — all errors are captured in the result object.
    """
    result = XLSXParseResult()

    # ── Step 1: Load workbook ─────────────────────────────────
    try:
        wb = openpyxl.load_workbook(
            io.BytesIO(file_bytes),
            read_only=True,
            data_only=True,
        )
    except Exception as e:
        result.file_errors.append(f"Could not read XLSX file: {str(e)}")
        return result

    ws = wb.active
    if ws is None:
        result.file_errors.append("XLSX file has no active sheet")
        return result

    # ── Step 2: Extract and validate headers ──────────────────
    rows = list(ws.iter_rows(values_only=True))

    if not rows:
        result.file_errors.append("XLSX file is empty")
        return result

    # First row is the header
    raw_headers = [str(h).strip().lower() if h is not None else "" for h in rows[0]]
    headers     = raw_headers

    # Check all required columns are present
    missing_cols = REQUIRED_COLUMNS - set(headers)
    if missing_cols:
        result.file_errors.append(
            f"Missing required columns: {', '.join(sorted(missing_cols))}. "
            f"Expected: {', '.join(sorted(REQUIRED_COLUMNS))}"
        )
        return result

    data_rows = rows[1:]  # everything after header

    if not data_rows:
        result.file_errors.append("XLSX file has a header but no data rows")
        return result

    # ── Step 3: Validate each data row ───────────────────────
    # Row numbers are 1-indexed and offset by 2
    # (row 1 = header, row 2 = first data row)
    for i, raw_row in enumerate(data_rows, start=2):

        # Skip completely empty rows (common in Excel files)
        if all(cell is None or str(cell).strip() == "" for cell in raw_row):
            continue

        # Map header names to cell values
        row_dict = {
            headers[j]: raw_row[j]
            for j in range(min(len(headers), len(raw_row)))
        }

        parsed_row, row_error = _validate_row(row_dict, row_number=i)

        if parsed_row:
            result.valid_rows.append(parsed_row)
        else:
            result.row_errors.append(row_error)

    return result