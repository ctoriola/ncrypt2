#!/usr/bin/env python3
"""
Script to generate a secure admin password hash for NCryp
"""

import hashlib
import hmac
import secrets
import string
import sys

def generate_password_hash(password):
    """Generate a secure hash for the admin password"""
    # Use HMAC-SHA256 for secure password hashing
    salt = secrets.token_hex(16)
    hash_obj = hmac.new(salt.encode(), password.encode(), hashlib.sha256)
    return f"{salt}:{hash_obj.hexdigest()}"

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    print("NCryp Admin Password Generator")
    print("=" * 40)
    
    if len(sys.argv) > 1:
        password = sys.argv[1]
        print(f"Using provided password: {password}")
    else:
        # Generate a secure password
        password = generate_secure_password()
        print(f"Generated secure password: {password}")
        print("\n⚠️  IMPORTANT: Save this password securely!")
    
    # Generate hash
    password_hash = generate_password_hash(password)
    
    print("\n" + "=" * 40)
    print("Add this to your env.local file:")
    print("=" * 40)
    print(f"ADMIN_USERNAME=admin")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    print("=" * 40)
    
    print("\nOr update your existing env.local file with:")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    
    print("\nDefault admin credentials:")
    print(f"Username: admin")
    print(f"Password: {password}")

if __name__ == "__main__":
    main() 