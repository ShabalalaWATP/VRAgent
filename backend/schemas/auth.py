"""Authentication schemas for request/response validation."""
from datetime import datetime
from typing import Optional
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRole(str, Enum):
    """User role enumeration."""
    USER = "user"
    ADMIN = "admin"


class AccountStatus(str, Enum):
    """Account status enumeration."""
    PENDING = "pending"
    APPROVED = "approved"
    SUSPENDED = "suspended"


# ============================================================================
# Request Schemas
# ============================================================================

class UserCreate(BaseModel):
    """Schema for user registration request."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    """Schema for login request (alternative to OAuth2 form)."""
    email: EmailStr
    password: str


class TokenRefresh(BaseModel):
    """Schema for token refresh request."""
    refresh_token: str


class PasswordChange(BaseModel):
    """Schema for password change request."""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class AdminPasswordChange(BaseModel):
    """Schema for admin changing user password."""
    new_password: str = Field(..., min_length=8, max_length=128)


class AdminUserCreate(BaseModel):
    """Schema for admin creating a user."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.USER


class RoleUpdate(BaseModel):
    """Schema for updating user role."""
    role: UserRole


class ProfileUpdate(BaseModel):
    """Schema for updating user profile."""
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=500)


# ============================================================================
# Response Schemas
# ============================================================================

class Token(BaseModel):
    """Schema for token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Schema for decoded token data."""
    user_id: Optional[int] = None
    email: Optional[str] = None
    role: Optional[str] = None


class UserResponse(BaseModel):
    """Schema for user response (public info)."""
    id: int
    email: str
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    role: UserRole
    status: AccountStatus
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class UserListResponse(BaseModel):
    """Schema for list of users response."""
    users: list[UserResponse]
    total: int


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    detail: Optional[str] = None
