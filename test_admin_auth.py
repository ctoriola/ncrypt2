#!/usr/bin/env python3
"""
Test script to debug admin authentication
"""

import requests
import json

def test_admin_auth():
    base_url = "http://localhost:5000"
    
    print("Testing Admin Authentication")
    print("=" * 40)
    
    # Test 1: Health check
    print("1. Testing health check...")
    try:
        response = requests.get(f"{base_url}/api/health")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 2: Admin login
    print("2. Testing admin login...")
    login_data = {
        "username": "admin",
        "password": "ub#49*KTvKAa"
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/admin/login",
            json=login_data,
            headers={"Content-Type": "application/json"}
        )
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("   ✅ Login successful!")
            cookies = response.cookies
            
            # Test 3: Get admin stats
            print("\n3. Testing admin stats...")
            stats_response = requests.get(
                f"{base_url}/api/admin/stats",
                cookies=cookies
            )
            print(f"   Status: {stats_response.status_code}")
            print(f"   Response: {stats_response.text}")
            
            # Test 4: Get admin files
            print("\n4. Testing admin files...")
            files_response = requests.get(
                f"{base_url}/api/admin/files",
                cookies=cookies
            )
            print(f"   Status: {files_response.status_code}")
            print(f"   Response: {files_response.text}")
            
        else:
            print("   ❌ Login failed!")
            
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    print("=" * 40)
    print("Test completed!")

if __name__ == "__main__":
    test_admin_auth() 