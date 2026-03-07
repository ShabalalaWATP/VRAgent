"""Regression tests for authentication service password verification."""

from passlib.hash import pbkdf2_sha256

from backend.models.models import User
from backend.services.auth_service import authenticate_user


def _create_user(db, username: str, email: str, password_hash: str) -> User:
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role="user",
        status="approved",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_authenticate_user_supports_legacy_pbkdf2_hash(db):
    """Users with legacy PBKDF2 hashes should still be able to log in."""
    legacy_hash = pbkdf2_sha256.hash("admin123")
    user = _create_user(db, "alexorr", "alexorr@example.com", legacy_hash)

    authenticated = authenticate_user(db, "alexorr", "admin123")

    assert authenticated is not None
    assert authenticated.id == user.id

    # Hash should be upgraded to current bcrypt policy after successful login.
    db.refresh(user)
    assert user.password_hash != legacy_hash
    assert user.password_hash.startswith("$2")


def test_authenticate_user_with_invalid_hash_returns_none(db):
    """Malformed hashes must not crash login and should fail authentication."""
    _create_user(db, "brokenhash", "brokenhash@example.com", "not-a-valid-hash")

    authenticated = authenticate_user(db, "brokenhash", "admin123")

    assert authenticated is None


def test_authenticate_user_supports_legacy_plaintext_password_row(db):
    """Plain-text legacy rows should authenticate once and be re-hashed."""
    user = _create_user(db, "legacyplain", "legacyplain@example.com", "admin123")

    authenticated = authenticate_user(db, "legacyplain", "admin123")

    assert authenticated is not None
    assert authenticated.id == user.id

    db.refresh(user)
    assert user.password_hash != "admin123"
    assert user.password_hash.startswith("$2")
