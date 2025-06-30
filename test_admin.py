#!/usr/bin/env python3
"""
Test script to debug admin authentication and API endpoints
"""

import requests
import json

BASE_URL = "http://localhost:5000"

def test_admin_login():
    """Test admin login"""
    print("Testing admin login...")
    
    login_data = {
        "username": "admin",
        "password": "ub#49*KTvKAa"
    }
    
    response = requests.post(
        f"{BASE_URL}/api/admin/login",
        json=login_data,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Login Status Code: {response.status_code}")
    print(f"Login Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Login successful!")
        return response.cookies
    else:
        print("❌ Login failed!")
        return None

def test_admin_stats(cookies):
    """Test admin stats endpoint"""
    print("\nTesting admin stats...")
    
    response = requests.get(
        f"{BASE_URL}/api/admin/stats",
        cookies=cookies
    )
    
    print(f"Stats Status Code: {response.status_code}")
    print(f"Stats Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Stats loaded successfully!")
    else:
        print("❌ Stats failed!")

def test_admin_files(cookies):
    """Test admin files endpoint"""
    print("\nTesting admin files...")
    
    response = requests.get(
        f"{BASE_URL}/api/admin/files",
        cookies=cookies
    )
    
    print(f"Files Status Code: {response.status_code}")
    print(f"Files Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Files loaded successfully!")
    else:
        print("❌ Files failed!")

def test_health_check():
    """Test health check endpoint"""
    print("\nTesting health check...")
    
    response = requests.get(f"{BASE_URL}/api/health")
    
    print(f"Health Status Code: {response.status_code}")
    print(f"Health Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Health check successful!")
    else:
        print("❌ Health check failed!")

def main():
    print("NCryp Admin API Test")
    print("=" * 40)
    
    # Test health check first
    test_health_check()
    
    # Test admin login
    cookies = test_admin_login()
    
    if cookies:
        # Test admin endpoints
        test_admin_stats(cookies)
        test_admin_files(cookies)
        
        # Test logout
        print("\nTesting admin logout...")
        logout_response = requests.post(
            f"{BASE_URL}/api/admin/logout",
            cookies=cookies
        )
        print(f"Logout Status Code: {logout_response.status_code}")
        print(f"Logout Response: {logout_response.text}")
    else:
        print("Skipping admin endpoint tests due to login failure")

if __name__ == "__main__":
    main() 