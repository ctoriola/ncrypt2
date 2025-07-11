#!/usr/bin/env python3
"""
Test script to test admin login and dashboard functionality
"""

import requests
import json

# API base URL
API_BASE_URL = 'https://web-production-5d61.up.railway.app'

def test_admin_login():
    """Test admin login functionality"""
    try:
        print("Testing admin login...")
        
        login_data = {
            'email': 'toriola333@gmail.com',
            'password': 'D3m1lad3!!'
        }
        
        response = requests.post(
            f'{API_BASE_URL}/api/admin/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Admin login response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Admin login successful!")
            print(f"Response: {json.dumps(data, indent=2)}")
            return True
        else:
            print(f"✗ Admin login failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error testing admin login: {e}")
        return False

def test_admin_stats():
    """Test admin stats endpoint (requires authentication)"""
    try:
        print("\nTesting admin stats endpoint...")
        
        # First try without authentication (should fail)
        response = requests.get(f'{API_BASE_URL}/api/admin/stats')
        print(f"Admin stats without auth: {response.status_code}")
        if response.status_code == 401:
            print("✓ Correctly requires authentication")
        else:
            print(f"Unexpected response: {response.text}")
            
    except Exception as e:
        print(f"Error testing admin stats: {e}")

def test_session_endpoint():
    """Test session endpoint to see if sessions are working"""
    try:
        print("\nTesting session endpoint...")
        
        response = requests.get(f'{API_BASE_URL}/api/admin/test-session')
        print(f"Session test response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Session test successful!")
            print(f"Session data: {json.dumps(data, indent=2)}")
        else:
            print(f"Session test failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing session: {e}")

if __name__ == '__main__':
    print("Testing admin dashboard functionality...")
    print("="*50)
    
    test_admin_login()
    test_admin_stats()
    test_session_endpoint()
    
    print("\n" + "="*50)
    print("To test the full admin dashboard:")
    print("1. Go to your NCryp application")
    print("2. Navigate to the admin login page")
    print("3. Login with username: toriola333@gmail.com, password: D3m1lad3!!")
    print("4. Check the dashboard stats - you should see:")
    print("   - Registered users count (should be > 0 from our tests)")
    print("   - Live visitors count")
    print("   - Total visits count")
    print("5. Try registering a new user and see if the stats update") 