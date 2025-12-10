#!/usr/bin/env python3
"""
Script to create the initial admin user.

Run this after the database migration to create the first admin account.

Usage:
    python create_admin.py --email admin@example.com --username admin --password YourSecurePassword123
"""
import argparse
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from backend.core.database import SessionLocal
from backend.services.auth_service import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    count_users,
)
from backend.core.logging import get_logger

logger = get_logger(__name__)


def create_admin_user(email: str, username: str, password: str) -> bool:
    """Create an admin user."""
    db: Session = SessionLocal()
    try:
        # Check if email exists
        if get_user_by_email(db, email):
            print(f"Error: Email '{email}' already exists.")
            return False
        
        # Check if username exists
        if get_user_by_username(db, username):
            print(f"Error: Username '{username}' already exists.")
            return False
        
        # Create the admin user
        user = create_user(
            db=db,
            email=email,
            username=username,
            password=password,
            role="admin",
            status="approved",
        )
        
        print(f"✓ Admin user created successfully!")
        print(f"  Email: {user.email}")
        print(f"  Username: {user.username}")
        print(f"  Role: {user.role}")
        print(f"  Status: {user.status}")
        return True
        
    except Exception as e:
        print(f"Error creating admin user: {e}")
        return False
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Create an admin user for VRAgent")
    parser.add_argument("--email", required=True, help="Admin email address")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", required=True, help="Admin password (min 8 characters)")
    
    args = parser.parse_args()
    
    # Validate password length
    if len(args.password) < 8:
        print("Error: Password must be at least 8 characters long.")
        sys.exit(1)
    
    # Check total users - warn if this isn't the first user
    db = SessionLocal()
    try:
        total = count_users(db)
        if total > 0:
            print(f"Note: There are already {total} user(s) in the database.")
            response = input("Continue creating admin user? (y/N): ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(0)
    finally:
        db.close()
    
    success = create_admin_user(args.email, args.username, args.password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
