"""Admin routes for user management."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.auth import get_current_admin_user
from backend.models.models import User
from backend.schemas.auth import (
    AdminPasswordChange,
    AdminUserCreate,
    MessageResponse,
    RoleUpdate,
    UserResponse,
)
from backend.services.auth_service import (
    create_user,
    delete_user,
    get_all_users,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    update_user_password,
    update_user_role,
    update_user_status,
)

router = APIRouter(prefix="/admin", tags=["admin"])
logger = get_logger(__name__)


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Get list of all users (admin only).
    """
    users = get_all_users(db, skip=skip, limit=limit)
    return [UserResponse.model_validate(u) for u in users]


@router.post("/users", response_model=UserResponse)
async def create_user_admin(
    user_data: AdminUserCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Create a new user with specified role (admin only).
    
    User is created with 'approved' status, bypassing the approval process.
    """
    # Check if email already exists
    if get_user_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Check if username already exists
    if get_user_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )
    
    # Create user with approved status
    user = create_user(
        db=db,
        email=user_data.email,
        username=user_data.username,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        password=user_data.password,
        role=user_data.role.value,
        status="approved",
    )
    
    logger.info(f"Admin {current_admin.email} created user: {user.email} with role {user.role}")
    
    return UserResponse.model_validate(user)


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Get a specific user by ID (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", response_model=MessageResponse)
async def delete_user_admin(
    user_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Delete a user and all their data (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Prevent self-deletion
    if user.id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    
    email = user.email
    delete_user(db, user)
    
    logger.info(f"Admin {current_admin.email} deleted user: {email}")
    
    return MessageResponse(message=f"User {email} deleted successfully")


@router.post("/users/{user_id}/approve", response_model=UserResponse)
async def approve_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Approve a pending user account (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    user = update_user_status(db, user, "approved")
    
    logger.info(f"Admin {current_admin.email} approved user: {user.email}")
    
    return UserResponse.model_validate(user)


@router.post("/users/{user_id}/suspend", response_model=UserResponse)
async def suspend_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Suspend a user account (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Prevent self-suspension
    if user.id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend your own account",
        )
    
    user = update_user_status(db, user, "suspended")
    
    logger.info(f"Admin {current_admin.email} suspended user: {user.email}")
    
    return UserResponse.model_validate(user)


@router.put("/users/{user_id}/role", response_model=UserResponse)
async def update_role(
    user_id: int,
    role_data: RoleUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Update a user's role (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Prevent removing own admin role
    if user.id == current_admin.id and role_data.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin privileges",
        )
    
    user = update_user_role(db, user, role_data.role.value)
    
    logger.info(f"Admin {current_admin.email} changed role for {user.email} to {user.role}")
    
    return UserResponse.model_validate(user)


@router.put("/users/{user_id}/password", response_model=MessageResponse)
async def change_user_password(
    user_id: int,
    password_data: AdminPasswordChange,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Change a user's password (admin only).
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    update_user_password(db, user, password_data.new_password)
    
    logger.info(f"Admin {current_admin.email} changed password for user: {user.email}")
    
    return MessageResponse(message=f"Password changed for {user.email}")
