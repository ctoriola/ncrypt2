#!/usr/bin/env python3
"""
Generate a secure admin API key for NCryp
"""

import secrets
import string
import os

def generate_api_key(length=32):
    """Generate a secure random API key"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def update_env_file(api_key):
    """Update env.local with the new API key"""
    env_file = 'env.local'
    
    # Read existing content
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            content = f.read()
    else:
        content = ''
    
    # Check if ADMIN_API_KEY already exists
    if 'ADMIN_API_KEY=' in content:
        # Replace existing key
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('ADMIN_API_KEY='):
                lines[i] = f'ADMIN_API_KEY={api_key}'
                break
        content = '\n'.join(lines)
    else:
        # Add new key
        if content and not content.endswith('\n'):
            content += '\n'
        content += f'ADMIN_API_KEY={api_key}\n'
    
    # Write back to file
    with open(env_file, 'w') as f:
        f.write(content)
    
    print(f"✅ Admin API key generated and added to {env_file}")
    print(f"🔑 API Key: {api_key}")
    print("\n📝 Instructions:")
    print("1. Use this API key in your frontend when Firebase is not available")
    print("2. Keep this key secure and don't share it publicly")
    print("3. For production, set this as an environment variable in Railway")

if __name__ == '__main__':
    api_key = generate_api_key()
    update_env_file(api_key) 