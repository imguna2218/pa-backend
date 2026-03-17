"""
config.py — Single source of truth for all environment variables.
All other modules import from here, never directly from os.environ.
"""

import os
from dotenv import load_dotenv

load_dotenv()


def _require(key: str) -> str:
    """Raise a clear error at startup if a required env var is missing."""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return value


# ─── Database ─────────────────────────────────────────────────────────────────
POSTGRES_USER     = _require("POSTGRES_USER")
POSTGRES_PASSWORD = _require("POSTGRES_PASSWORD")
POSTGRES_DB       = _require("POSTGRES_DB")
POSTGRES_HOST     = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT     = int(os.getenv("POSTGRES_PORT", "5432"))

# asyncpg DSN format
DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# ─── JWT ──────────────────────────────────────────────────────────────────────
JWT_SECRET          = _require("JWT_SECRET")
JWT_ALGORITHM       = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES  = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# ─── Cookie ───────────────────────────────────────────────────────────────────
COOKIE_NAME     = os.getenv("COOKIE_NAME", "access_token")
COOKIE_SECURE   = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")
# Cookie max-age matches JWT expiry exactly
COOKIE_MAX_AGE  = JWT_EXPIRE_MINUTES * 60

# ─── Seed Super Admin ─────────────────────────────────────────────────────────
SEED_SUPER_ADMIN_FIRST_NAME = _require("SEED_SUPER_ADMIN_FIRST_NAME")
SEED_SUPER_ADMIN_LAST_NAME  = _require("SEED_SUPER_ADMIN_LAST_NAME")
SEED_SUPER_ADMIN_EMAIL      = _require("SEED_SUPER_ADMIN_EMAIL")
SEED_SUPER_ADMIN_PASSWORD   = _require("SEED_SUPER_ADMIN_PASSWORD")