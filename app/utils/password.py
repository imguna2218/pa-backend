"""
utils/password.py — Password hashing and verification using bcrypt.

bcrypt automatically generates and embeds a unique salt into every hash,
so two calls to hash_password("same_password") produce different hashes —
this is by design and is what makes bcrypt secure against rainbow tables.

We use passlib as the bcrypt wrapper because it handles:
  - Salt generation internally (no manual salt needed)
  - Correct rounds/cost factor (default 12 — good balance of security vs speed)
  - Safe constant-time comparison to prevent timing attacks
"""

from passlib.context import CryptContext

# CryptContext manages the hashing scheme.
# schemes=["bcrypt"]  → use bcrypt exclusively
# deprecated="auto"   → if we ever add a new scheme, old hashes auto-upgrade on next login
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """
    Hash a plain-text password using bcrypt with auto-generated salt.

    Args:
        plain: The raw password string from the user.

    Returns:
        A bcrypt hash string (~60 chars) that includes the salt, cost factor,
        and hash — everything needed to verify later.

    Example:
        hash_password("MySecret@123")
        → "$2b$12$SomeSaltEmbeddedHereXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    """
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    Uses constant-time comparison internally to prevent timing attacks.

    Args:
        plain:  The raw password string the user just typed.
        hashed: The bcrypt hash stored in the database.

    Returns:
        True if the password matches, False otherwise.
        Never raises — returns False on any internal error.
    """
    try:
        return _pwd_context.verify(plain, hashed)
    except Exception:
        # Malformed hash in DB or any other unexpected issue → treat as mismatch
        return False