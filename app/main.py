"""
main.py — FastAPI application entry point.

Lifespan:
  1. Initialise asyncpg connection pool
  2. Seed default super_admin from .env (idempotent — skips if already exists)
  3. Graceful pool shutdown on exit

Swagger UI : /docs
ReDoc      : /redoc
Health     : GET /health
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    SEED_SUPER_ADMIN_EMAIL,
    SEED_SUPER_ADMIN_FIRST_NAME,
    SEED_SUPER_ADMIN_LAST_NAME,
    SEED_SUPER_ADMIN_PASSWORD,
)
from app.database import close_pool, get_connection, init_pool
from app.routers.auth        import router as auth_router
from app.routers.profile     import router as profile_router
from app.routers.super_admin import router as super_admin_router


# ─────────────────────────────────────────────────────────────────────────────
# Seed helper
# ─────────────────────────────────────────────────────────────────────────────

async def seed_super_admin() -> None:
    """
    Ensure exactly one seeded super_admin exists at startup.
    Idempotent — if the email already exists in DB, does nothing.
    """
    from app.utils.password import hash_password

    async with get_connection() as conn:
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1",
            SEED_SUPER_ADMIN_EMAIL,
        )
        if existing:
            print(f"[seed] Super admin already exists -> {SEED_SUPER_ADMIN_EMAIL}")
            return

        hashed = hash_password(SEED_SUPER_ADMIN_PASSWORD)
        await conn.execute(
            """
            INSERT INTO users (first_name, last_name, email, password, role)
            VALUES ($1, $2, $3, $4, 'super_admin')
            """,
            SEED_SUPER_ADMIN_FIRST_NAME,
            SEED_SUPER_ADMIN_LAST_NAME,
            SEED_SUPER_ADMIN_EMAIL,
            hashed,
        )
        print(f"[seed] Super admin created -> {SEED_SUPER_ADMIN_EMAIL}")


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[startup] Initialising database pool ...")
    await init_pool()
    print("[startup] Pool ready.")
    print("[startup] Seeding super admin ...")
    await seed_super_admin()
    print("[startup] Ready to serve requests.")

    yield

    print("[shutdown] Closing database pool ...")
    await close_pool()
    print("[shutdown] Shutdown complete.")


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="RBAC Backend API",
    description="""
## Role-Based Access Control (RBAC) Backend

A secure FastAPI backend with three roles: **super_admin**, **admin**, and **user**.

### Authentication
- All authentication uses **HttpOnly JWT cookies** — no Bearer tokens.
- One unified login endpoint auto-detects role from the database.
- Deleted accounts are blocked at every protected route instantly.

### Roles and Capabilities

| Role | Can Do |
|---|---|
| `user` | Self-register, login, view/edit own profile |
| `admin` | Login (created by super_admin), view/edit own profile |
| `super_admin` | All of the above + create/delete accounts, bulk XLSX upload, list all users |

### Key Rules
- **No path parameters** — all IDs and filters go in the request body.
- **Soft delete only** — records are never hard-deleted (deleted=TRUE).
- **super_admin cannot delete themselves**.
- **One login route** for all roles — role is resolved from the database.

### Getting Started
1. Start the database: `docker-compose up -d`
2. Run the server: `uvicorn app.main:app --reload`
3. Login with the seeded super admin credentials from `.env`
""",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    openapi_tags=[
        {
            "name": "Health",
            "description": "Server liveness probe.",
        },
        {
            "name": "Auth",
            "description": (
                "Login (all roles), signup (users only), logout. "
                "JWT delivered via HttpOnly cookie."
            ),
        },
        {
            "name": "Profile",
            "description": (
                "View and edit your own profile. "
                "Available to all authenticated roles."
            ),
        },
        {
            "name": "Super Admin",
            "description": (
                "Account management: create, bulk-create via XLSX, "
                "soft-delete, and list users. super_admin role only."
            ),
        },
    ],
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# allow_credentials=True is required for HttpOnly cookies to be sent cross-origin.
# Replace allow_origins=["*"] with your actual frontend domain(s) in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth_router,        prefix="/auth",        tags=["Auth"])
app.include_router(profile_router,     prefix="/profile",     tags=["Profile"])
app.include_router(super_admin_router, prefix="/super-admin", tags=["Super Admin"])


# ── Health check ─────────────────────────────────────────────────────────────
@app.get(
    "/health",
    tags=["Health"],
    summary="Liveness probe",
    description="Returns 200 OK if the server is running. No auth required.",
)
async def health_check():
    return {"status": "ok"}