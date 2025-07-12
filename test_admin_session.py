#!/usr/bin/env python3
"""
Test script to check admin session status
"""

import requests
import json

# API base URL
API_BASE_URL = 'https://web-production-5d61.up.railway.app'

def test_admin_session():
    """Test admin session status"""
    try:
        print("Testing admin session status...")
        
        # Test session endpoint
        response = requests.get(f'{API_BASE_URL}/api/admin/test-session')
        print(f"Session test response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Session test successful!")
            print(f"Session data: {json.dumps(data, indent=2)}")
            print(f"Admin logged in: {data.get('admin_logged_in', False)}")
        else:
            print(f"Session test failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing session: {e}")

def test_admin_login_with_session():
    """Test admin login and maintain session"""
    try:
        print("\nTesting admin login with session...")
        
        # Create a session object to maintain cookies
        session = requests.Session()
        
        # Test admin login
        login_data = {
            'email': 'toriola333@gmail.com',
            'password': 'D3m1lad3!!'
        }
        
        response = session.post(
            f'{API_BASE_URL}/api/admin/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Admin login response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Admin login successful!")
            
            # Now test admin stats with the session
            stats_response = session.get(f'{API_BASE_URL}/api/admin/stats')
            print(f"Admin stats response: {stats_response.status_code}")
            if stats_response.status_code == 200:
                data = stats_response.json()
                print("✓ Admin stats accessible!")
                print(f"Stats: {json.dumps(data, indent=2)}")
            else:
                print(f"Admin stats failed: {stats_response.text}")
        else:
            print(f"✗ Admin login failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing admin login with session: {e}")

if __name__ == '__main__':
    test_admin_session()
    test_admin_login_with_session() 