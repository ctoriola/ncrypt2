#!/usr/bin/env python3
"""
Railway Setup Helper Script for NCryp (Postgres)

This script helps generate the required values for Railway deployment with Postgres.
"""

import secrets
import hashlib
import os
import json
from datetime import datetime

def generate_secret_key():
    """Generate a secure secret key for Flask"""
    return secrets.token_hex(32)

def create_railway_env_template():
    """Create a template for Railway environment variables"""
    secret_key = generate_secret_key()
    
    template = f"""# Railway Environment Variables Template (Postgres)
# Copy these values to your Railway project variables

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY={secret_key}

# Database Configuration
DATABASE_URL=your-railway-postgres-url

# Storage Configuration (choose one)
STORAGE_TYPE=local
LOCAL_STORAGE_PATH=./uploads

# CORS Configuration
CORS_ORIGINS=*

# File Upload Limits
MAX_FILE_SIZE=104857600
ALLOWED_EXTENSIONS=pdf,txt,jpg,jpeg,png,gif,doc,docx,xls,xlsx,csv,zip,rar

# Optional: Cloud Storage (uncomment and configure as needed)
# AWS_ACCESS_KEY_ID=your-aws-access-key
# AWS_SECRET_ACCESS_KEY=your-aws-secret-key
# AWS_REGION=us-east-1
# S3_BUCKET_NAME=your-bucket-name

# GCS_BUCKET_NAME=your-bucket-name
# AZURE_CONNECTION_STRING=your-azure-connection-string
# AZURE_CONTAINER_NAME=your-container-name
"""
    
    return template

def main():
    """Main function to run the setup"""
    print("🚂 Railway Setup Helper for NCryp (Postgres)")
    print("=" * 50)
    
    # Generate values
    template = create_railway_env_template()
    
    # Save template to file
    with open('railway.env.template', 'w') as f:
        f.write(template)
    
    print("\n✅ Generated Railway environment template:")
    print("📁 File: railway.env.template")
    print("\n📋 Next steps:")
    print("1. Add Postgres database to your Railway project")
    print("2. Copy the DATABASE_URL to your environment variables")
    print("3. Copy the contents of railway.env.template to your Railway project variables")
    print("4. Deploy your application")
    print("5. Run 'python create_admin.py' to create your first admin user")
    
    print("\n🔧 Postgres Setup:")
    print("1. In Railway dashboard, click 'New' → 'Database' → 'PostgreSQL'")
    print("2. Copy the DATABASE_URL from the database service")
    print("3. Add DATABASE_URL to your environment variables")
    
    print("\n👤 Admin User Setup:")
    print("1. After deployment, run: python create_admin.py")
    print("2. Follow the prompts to create your admin user")
    print("3. Use those credentials to log into the admin dashboard")
    
    print("\n📖 For detailed instructions, see RAILWAY_SETUP.md")

if __name__ == "__main__":
    main() 