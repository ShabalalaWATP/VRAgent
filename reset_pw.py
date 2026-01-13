#!/usr/bin/env python3
"""Quick password reset - connects to localhost:5432"""
import bcrypt
from sqlalchemy import create_engine, text

DATABASE_URL = 'postgresql+psycopg2://vragent:vragent_secret@localhost:5432/vragent'

engine = create_engine(DATABASE_URL)
hashed = bcrypt.hashpw(b'test123', bcrypt.gensalt()).decode('utf-8')

with engine.connect() as conn:
    # First check current status
    result = conn.execute(text("SELECT id, username, status, password_hash FROM users WHERE username = 'alexorr'"))
    user = result.fetchone()
    if user:
        print(f"User found: id={user[0]}, username={user[1]}, status={user[2]}")
        print(f"Current hash: {user[3][:20]}...")
    else:
        print("User not found!")
        exit(1)
    
    # Update password and ensure status is approved
    result = conn.execute(
        text("UPDATE users SET password_hash = :hash, status = 'approved' WHERE username = 'alexorr'"),
        {'hash': hashed}
    )
    conn.commit()
    print(f"Rows updated: {result.rowcount}")
    print(f"New hash: {hashed[:20]}...")
    print("Password set to: test123, status set to: approved")
