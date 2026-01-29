"""Authentication service for password hashing and JWT token management."""
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib

import bcrypt
import redis
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.models.models import User

logger = get_logger(__name__)

# JWT Settings from config
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.refresh_token_expire_days

# Token blacklist prefix
TOKEN_BLACKLIST_PREFIX = "vragent:token_blacklist:"

# Redis client for token blacklist (lazy initialization)
_redis_client: Optional[redis.Redis] = None


def _get_redis_client() -> Optional[redis.Redis]:
    """Get Redis client for token blacklist (lazy initialization)."""
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
            _redis_client.ping()
        except Exception as e:
            logger.warning(f"Redis not available for token blacklist: {e}")
            _redis_client = None
    return _redis_client


def _get_token_hash(token: str) -> str:
    """Get a short hash of the token for storage (don't store full tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()[:32]


def blacklist_token(token: str, expires_in_seconds: int = None) -> bool:
    """
    Add a token to the blacklist.

    Args:
        token: The JWT token to blacklist
        expires_in_seconds: TTL for blacklist entry (defaults to token expiry)

    Returns:
        True if successfully blacklisted, False if Redis unavailable
    """
    client = _get_redis_client()
    if not client:
        logger.warning("Cannot blacklist token: Redis unavailable")
        return False

    try:
        token_hash = _get_token_hash(token)
        # Default TTL: max of access and refresh token expiry
        if expires_in_seconds is None:
            expires_in_seconds = max(
                ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
            )

        client.setex(f"{TOKEN_BLACKLIST_PREFIX}{token_hash}", expires_in_seconds, "1")
        logger.info(f"Token blacklisted: {token_hash[:8]}...")
        return True
    except Exception as e:
        logger.error(f"Failed to blacklist token: {e}")
        return False


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token is blacklisted.

    Args:
        token: The JWT token to check

    Returns:
        True if blacklisted, False otherwise (including Redis unavailable)
    """
    client = _get_redis_client()
    if not client:
        # If Redis is unavailable, allow token (fail open for availability)
        return False

    try:
        token_hash = _get_token_hash(token)
        return client.exists(f"{TOKEN_BLACKLIST_PREFIX}{token_hash}") > 0
    except Exception as e:
        logger.error(f"Failed to check token blacklist: {e}")
        return False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT token."""
    try:
        # Check if token is blacklisted first
        if is_token_blacklisted(token):
            logger.warning("Token is blacklisted")
            return None

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        return None


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get user by email address."""
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """Get user by ID."""
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username."""
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password."""
    user = get_user_by_username(db, username)
    if not user:
        logger.info(f"Login attempt failed: user not found for username {username}")
        return None
    if not user.password_hash:
        logger.warning(f"Login attempt failed: no password set for user {username}")
        return None
    if not verify_password(password, user.password_hash):
        logger.info(f"Login attempt failed: invalid password for user {username}")
        return None
    return user


def create_user(
    db: Session,
    email: str,
    username: str,
    password: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    role: str = "user",
    status: str = "pending",
) -> User:
    """Create a new user."""
    hashed_password = get_password_hash(password)
    user = User(
        email=email,
        username=username,
        first_name=first_name,
        last_name=last_name,
        password_hash=hashed_password,
        role=role,
        status=status,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"Created new user: {email} ({first_name} {last_name}) with role {role} and status {status}")
    return user


def update_user_password(db: Session, user: User, new_password: str) -> User:
    """Update user's password."""
    user.password_hash = get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    logger.info(f"Password updated for user: {user.email}")
    return user


def update_user_status(db: Session, user: User, status: str) -> User:
    """Update user's account status."""
    old_status = user.status
    user.status = status
    db.commit()
    db.refresh(user)
    logger.info(f"User {user.email} status changed from {old_status} to {status}")
    return user


def update_user_role(db: Session, user: User, role: str) -> User:
    """Update user's role."""
    old_role = user.role
    user.role = role
    db.commit()
    db.refresh(user)
    logger.info(f"User {user.email} role changed from {old_role} to {role}")
    return user


def update_last_login(db: Session, user: User) -> User:
    """Update user's last login timestamp."""
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user


def get_all_users(db: Session, skip: int = 0, limit: int = 100) -> list[User]:
    """Get all users with pagination."""
    return db.query(User).offset(skip).limit(limit).all()


def get_users_by_status(db: Session, status: str) -> list[User]:
    """Get all users with a specific status."""
    return db.query(User).filter(User.status == status).all()


def delete_user(db: Session, user: User) -> bool:
    """Delete a user and their associated data."""
    from backend.models.models import Project, CodeChunk, Finding, Report, ScanRun
    
    # Get user's projects
    projects = db.query(Project).filter(Project.owner_id == user.id).all()
    
    for project in projects:
        # Delete associated data for each project
        db.query(Finding).filter(Finding.project_id == project.id).delete()
        db.query(Report).filter(Report.project_id == project.id).delete()
        db.query(ScanRun).filter(ScanRun.project_id == project.id).delete()
        db.query(CodeChunk).filter(CodeChunk.project_id == project.id).delete()
        db.delete(project)
    
    # Delete the user
    db.delete(user)
    db.commit()
    logger.info(f"Deleted user {user.email} and all associated data")
    return True


def count_users(db: Session) -> int:
    """Count total users."""
    return db.query(User).count()


def count_users_by_status(db: Session, status: str) -> int:
    """Count users by status."""
    return db.query(User).filter(User.status == status).count()
