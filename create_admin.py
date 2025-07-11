#!/usr/bin/env python3
"""
Create Admin User Script for NCryp

This script creates an admin user in the Postgres database.
"""

import os
import hashlib
import secrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, AdminUser
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def generate_password_hash(password):
    """Generate a password hash for admin authentication"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256()
    hash_obj.update((password + salt).encode('utf-8'))
    return f"{salt}${hash_obj.hexdigest()}"

def create_admin_user(username, password):
    """Create an admin user in the database"""
    # Get database URL from environment
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///ncryp.db')
    
    # Create engine and session
    engine = create_engine(DATABASE_URL, echo=False, future=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Create session
    db = SessionLocal()
    
    try:
        # Check if admin user already exists
        existing_user = db.query(AdminUser).filter_by(username=username).first()
        if existing_user:
            print(f"Admin user '{username}' already exists!")
            return False
        
        # Generate password hash
        password_hash = generate_password_hash(password)
        
        # Create new admin user
        admin_user = AdminUser(
            username=username,
            password_hash=password_hash
        )
        
        # Add to database
        db.add(admin_user)
        db.commit()
        
        print(f"✅ Admin user '{username}' created successfully!")
        print(f"🔑 Password: {password}")
        print("\n📋 Next steps:")
        print("1. Use these credentials to log into the admin dashboard")
        print("2. Change the password after first login for security")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def main():
    """Main function"""
    print("🔧 NCryp Admin User Creator")
    print("=" * 40)
    
    # Get admin credentials
    username = input("Enter admin username (default: admin): ").strip() or "admin"
    password = input("Enter admin password (default: admin123): ").strip() or "admin123"
    
    print(f"\nCreating admin user:")
    print(f"Username: {username}")
    print(f"Password: {password}")
    
    confirm = input("\nProceed? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Cancelled.")
        return
    
    # Create the admin user
    success = create_admin_user(username, password)
    
    if success:
        print("\n🎉 Admin user created successfully!")
        print("You can now log into the admin dashboard.")
    else:
        print("\n💥 Failed to create admin user.")
        print("Check your database connection and try again.")

if __name__ == "__main__":
    main() 