#!/usr/bin/env python3
"""
Test script to simulate browser session behavior
"""

import requests
import json

# API base URL
API_BASE_URL = 'https://web-production-5d61.up.railway.app'

def test_browser_like_session():
    """Test admin endpoints like a browser would"""
    try:
        print("Testing browser-like session behavior...")
        
        # Create a session object (like a browser)
        session = requests.Session()
        
        # First, check current session
        print("1. Checking current session...")
        response = session.get(f'{API_BASE_URL}/api/admin/test-session')
        print(f"Session test: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Admin logged in: {data.get('admin_logged_in', False)}")
        
        # Try to access admin stats without login (should fail)
        print("\n2. Trying admin stats without login...")
        response = session.get(f'{API_BASE_URL}/api/admin/stats')
        print(f"Admin stats without login: {response.status_code}")
        if response.status_code == 401:
            print("✓ Correctly requires authentication")
        
        # Login as admin
        print("\n3. Logging in as admin...")
        login_data = {
            'email': 'toriola333@gmail.com',
            'password': 'D3m1lad3!!'
        }
        
        response = session.post(
            f'{API_BASE_URL}/api/admin/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Login response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Login successful!")
            
            # Check session after login
            print("\n4. Checking session after login...")
            response = session.get(f'{API_BASE_URL}/api/admin/test-session')
            if response.status_code == 200:
                data = response.json()
                print(f"Admin logged in after login: {data.get('admin_logged_in', False)}")
            
            # Try admin stats with session
            print("\n5. Trying admin stats with session...")
            response = session.get(f'{API_BASE_URL}/api/admin/stats')
            print(f"Admin stats with session: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print("✓ Admin stats accessible!")
                print(f"Registered users: {data.get('user_stats', {}).get('total_registered_users', 0)}")
            else:
                print(f"Admin stats failed: {response.text}")
        else:
            print(f"✗ Login failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    test_browser_like_session() 