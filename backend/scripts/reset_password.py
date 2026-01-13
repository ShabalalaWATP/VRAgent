#!/usr/bin/env python3
"""Reset user password script."""
import sys
import bcrypt
from sqlalchemy import create_engine, text
import os

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://vragent:vragent_secret@db:5432/vragent')

def reset_password(username: str, new_password: str):
    """Reset password for a user."""
    engine = create_engine(DATABASE_URL)
    
    # Generate new password hash
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    with engine.connect() as conn:
        # First check current user status
        result = conn.execute(
            text("SELECT id, username, status, password_hash FROM users WHERE username = :username"),
            {'username': username}
        )
        user = result.fetchone()
        
        if not user:
            print(f"User '{username}' not found")
            return
        
        print(f"Found user: id={user[0]}, username={user[1]}, status={user[2]}")
        print(f"Old hash prefix: {user[3][:30] if user[3] else 'None'}...")
        
        # Update the password AND set status to approved
        result = conn.execute(
            text("UPDATE users SET password_hash = :hash, status = 'approved' WHERE username = :username"),
            {'hash': hashed, 'username': username}
        )
        conn.commit()
        
        print(f"Rows updated: {result.rowcount}")
        print(f"New hash prefix: {hashed[:30]}...")
        print(f"Password set to: {new_password}")
        print(f"Status set to: approved")
        
        # Verify the password works
        print("\nVerifying password...")
        if bcrypt.checkpw(new_password.encode('utf-8'), hashed.encode('utf-8')):
            print("SUCCESS: Password verification passed!")
        else:
            print("ERROR: Password verification FAILED!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python reset_password.py <username> <new_password>")
        sys.exit(1)
    
    reset_password(sys.argv[1], sys.argv[2])
