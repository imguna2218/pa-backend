# RBAC Backend API

A robust Role-Based Access Control backend built with **FastAPI**, **PostgreSQL 15**, and **asyncpg**.  
Authentication via **bcrypt + JWT in HttpOnly cookies**. No ORM — raw SQL throughout.

---

## Roles

| Role | Created By | Capabilities |
|---|---|---|
| `user` | Self-register via `/auth/signup` | Login, view/edit own profile |
| `admin` | super_admin only | Login, view/edit own profile |
| `super_admin` | super_admin only (or seeded from `.env`) | Full account management |

---

## Tech Stack

- **Python 3.12** + **FastAPI 0.111**
- **PostgreSQL 15** (Docker)
- **asyncpg** — async PostgreSQL driver (no ORM)
- **passlib + bcrypt** — password hashing
- **python-jose** — JWT signing/verification
- **openpyxl** — XLSX parsing for bulk creation
- **Pydantic v2** — request/response validation

---

## Project Structure

```
app/
├── main.py                  # App entry, lifespan, router registration
├── config.py                # All env vars loaded here
├── database.py              # asyncpg pool init/teardown, get_connection()
├── dependencies.py          # get_current_user() — JWT cookie → DB → CurrentUser
├── middleware/
│   └── auth_middleware.py   # RBAC dependencies: require_super_admin, require_authenticated
├── routers/
│   ├── auth.py              # POST /auth/login|signup|logout
│   ├── profile.py           # GET /profile/me, PUT /profile/update
│   └── super_admin.py       # POST /super-admin/create-account|bulk-create|delete-account|users
├── services/
│   ├── auth_service.py      # Login, signup DB logic
│   ├── profile_service.py   # Get/update profile DB logic
│   └── super_admin_service.py # Account management DB logic
├── schemas/
│   ├── auth_schema.py       # Login/signup request + response models
│   ├── profile_schema.py    # Profile request + response models
│   └── super_admin_schema.py # Super admin request + response models
├── utils/
│   ├── password.py          # hash_password(), verify_password()
│   ├── jwt_handler.py       # create/decode token, set/clear cookie
│   └── xlsx_parser.py       # XLSX validation and row extraction
└── sql/
    └── init.sql             # Full schema — ENUMs, tables, indexes, triggers
docker-compose.yml
.env
requirements.txt
```

---

## Setup

### 1. Clone and configure environment

```bash
cp .env.example .env   # or edit .env directly
```

Edit `.env` — at minimum change these before production:

```env
JWT_SECRET=your-very-long-random-secret-here   # openssl rand -hex 32
SEED_SUPER_ADMIN_EMAIL=superadmin@yourdomain.com
SEED_SUPER_ADMIN_PASSWORD=YourStrongPassword1
COOKIE_SECURE=true   # set true when behind HTTPS
```

### 2. Start PostgreSQL

```bash
docker-compose up -d
```

The `init.sql` schema runs automatically on first container start.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the server

```bash
uvicorn app.main:app --reload
```

On first startup:
- The asyncpg connection pool is initialised
- The seeded super_admin is created (or skipped if already exists)
- Server is ready at `http://localhost:8000`

### 5. Open Swagger UI

```
http://localhost:8000/docs
```

---

## API Reference

### Auth — `/auth`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/login` | Public | Login for all roles. Sets HttpOnly JWT cookie. |
| POST | `/auth/signup` | Public | Register a new user account. |
| POST | `/auth/logout` | Public | Clear the JWT cookie. |

**Login request:**
```json
{ "email": "user@example.com", "password": "YourPass1" }
```

---

### Profile — `/profile`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/profile/me` | Any role | Get your own profile. |
| PUT | `/profile/update` | Any role | Update your own profile (partial — send only changed fields). |

**Update profile (change name only):**
```json
{ "first_name": "NewName" }
```

**Update profile (change password):**
```json
{
  "current_password": "OldPass1",
  "new_password": "NewPass2"
}
```

---

### Super Admin — `/super-admin`

All routes require `super_admin` role.

| Method | Path | Description |
|---|---|---|
| POST | `/super-admin/create-account` | Create a single admin or super_admin. |
| POST | `/super-admin/bulk-create` | Upload XLSX to create multiple accounts. |
| POST | `/super-admin/delete-account` | Soft-delete any account (not self). |
| POST | `/super-admin/users` | List all users with optional filters. |

**Create single account:**
```json
{
  "first_name": "Jane",
  "last_name": "Doe",
  "email": "jane@example.com",
  "password": "JanePass1",
  "role": "admin"
}
```

**Bulk create** — multipart/form-data with `.xlsx` file.

XLSX columns (order does not matter):
```
first_name | last_name | email | password | role
```
`role` must be `admin` or `super_admin`.

**Soft delete:**
```json
{ "target_user_id": "uuid-of-user-to-delete" }
```

**List users (with filters):**
```json
{ "role": "admin", "include_deleted": false }
```

---

## Security Notes

- **HttpOnly cookie** — JWT is never accessible to JavaScript. XSS-safe.
- **SameSite=lax** — Blocks CSRF from cross-site POST requests.
- **COOKIE_SECURE=true** — Enable in production (requires HTTPS).
- **bcrypt cost factor 12** — ~300ms per hash. Slow enough for security.
- **Live DB check on every request** — Deleted users are blocked immediately, not after token expiry.
- **No path params** — All input goes through the request body and Pydantic validation.
- **Soft delete only** — All records preserved. `deleted=TRUE` blocks login and all protected routes.

---

## XLSX Bulk Create Format

Download and fill this template:

| first_name | last_name | email | password | role |
|---|---|---|---|---|
| Alice | Smith | alice@company.com | AlicePass1 | admin |
| Bob | Jones | bob@company.com | BobPass1 | super_admin |

Rules:
- Column headers are case-insensitive and order-independent
- `role` must be exactly `admin` or `super_admin`
- Password: min 8 chars, 1 uppercase, 1 lowercase, 1 digit
- Duplicate emails are reported as per-row errors — remaining rows still process
- Completely blank rows are silently skipped

---

## Password Policy

All passwords (signup, profile update, bulk create) must have:
- Minimum **8 characters**
- At least **1 uppercase** letter
- At least **1 lowercase** letter
- At least **1 digit**