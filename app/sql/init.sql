-- =============================================================================
-- init.sql — Full database schema
-- Runs automatically when the PostgreSQL Docker container starts for the
-- first time (mounted at /docker-entrypoint-initdb.d/init.sql).
-- Safe to re-run: all statements use IF NOT EXISTS.
-- =============================================================================


-- ---------------------------------------------------------------------------
-- EXTENSIONS
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()


-- ---------------------------------------------------------------------------
-- ENUM TYPES
-- ---------------------------------------------------------------------------

-- User roles
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'user');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Request types (request_box)
DO $$ BEGIN
    CREATE TYPE request_type AS ENUM ('create_account', 'restore_account');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Request statuses (request_box)
DO $$ BEGIN
    CREATE TYPE request_status AS ENUM ('pending', 'approved', 'rejected');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;


-- ---------------------------------------------------------------------------
-- TABLES
-- ---------------------------------------------------------------------------

-- users -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name  TEXT            NOT NULL,
    last_name   TEXT            NOT NULL,
    email       TEXT            NOT NULL,
    password    TEXT            NOT NULL,           -- bcrypt hash
    role        user_role       NOT NULL DEFAULT 'user',
    deleted     BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_unique UNIQUE (email)
);

-- Automatically keep updated_at current on every UPDATE
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_users_updated_at ON users;
CREATE TRIGGER set_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- request_box -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_box (
    id                UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_email   TEXT            NOT NULL,
    request_type      request_type    NOT NULL,
    message           TEXT,                          -- optional note
    status            request_status  NOT NULL DEFAULT 'pending',
    reviewed_by       UUID            REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);


-- ---------------------------------------------------------------------------
-- INDEXES
-- ---------------------------------------------------------------------------

-- Fast lookup by email (login, duplicate check)
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (email);

-- Filter active (non-deleted) users quickly
CREATE INDEX IF NOT EXISTS idx_users_deleted
    ON users (deleted);

-- Super admin filters requests by status
CREATE INDEX IF NOT EXISTS idx_request_box_status
    ON request_box (status);

-- Look up all requests from a specific email
CREATE INDEX IF NOT EXISTS idx_request_box_requester_email
    ON request_box (requester_email);