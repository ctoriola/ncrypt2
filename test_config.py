#!/usr/bin/env python3
"""
Test script to validate Flask configuration
"""

from dotenv import load_dotenv
import os

def test_config():
    """Test the Flask configuration"""
    print("🔧 Testing Flask Configuration...")
    print("=" * 50)
    
    # Load environment variables
    load_dotenv('env.local')
    
    # Test basic configuration
    print(f"Storage Type: {os.getenv('STORAGE_TYPE', 'Not set')}")
    print(f"Flask Environment: {os.getenv('FLASK_ENV', 'Not set')}")
    print(f"Flask Debug: {os.getenv('FLASK_DEBUG', 'Not set')}")
    print(f"Secret Key: {'Set' if os.getenv('SECRET_KEY') else 'Not set'}")
    print(f"Max File Size: {os.getenv('MAX_FILE_SIZE', 'Not set')} bytes")
    print(f"Local Storage Path: {os.getenv('LOCAL_STORAGE_PATH', 'Not set')}")
    
    # Test file size conversion
    max_size = os.getenv('MAX_FILE_SIZE')
    if max_size:
        size_mb = int(max_size) / (1024 * 1024)
        print(f"Max File Size (MB): {size_mb:.1f} MB")
    
    # Test allowed extensions
    allowed_ext = os.getenv('ALLOWED_EXTENSIONS')
    if allowed_ext:
        extensions = allowed_ext.split(',')
        print(f"Allowed Extensions: {len(extensions)} types")
        print(f"  {', '.join(extensions[:5])}{'...' if len(extensions) > 5 else ''}")
    
    print("=" * 50)
    print("✅ Configuration test completed!")

if __name__ == "__main__":
    test_config() 