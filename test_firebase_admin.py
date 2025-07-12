#!/usr/bin/env python3
"""
Test script to verify Firebase authentication for admin endpoints
"""

import requests
import json

# API base URL
API_BASE_URL = 'https://web-production-5d61.up.railway.app'

def test_firebase_admin_auth():
    """Test Firebase authentication for admin endpoints"""
    try:
        print("Testing Firebase authentication for admin endpoints...")
        
        # Test admin stats endpoint without Firebase token (should fail)
        response = requests.get(f'{API_BASE_URL}/api/admin/stats')
        print(f"Admin stats without Firebase token: {response.status_code}")
        if response.status_code == 401:
            print("✓ Correctly requires Firebase authentication")
        else:
            print(f"Unexpected response: {response.text}")
            
        # Test admin files endpoint without Firebase token (should fail)
        response = requests.get(f'{API_BASE_URL}/api/admin/files')
        print(f"Admin files without Firebase token: {response.status_code}")
        if response.status_code == 401:
            print("✓ Correctly requires Firebase authentication")
        else:
            print(f"Unexpected response: {response.text}")
            
    except Exception as e:
        print(f"Error testing Firebase admin auth: {e}")

def test_session_vs_firebase():
    """Test that session-based admin login doesn't work for Firebase endpoints"""
    try:
        print("\nTesting session vs Firebase authentication...")
        
        # Create a session object to maintain cookies
        session = requests.Session()
        
        # Test admin login with session
        login_data = {
            'email': 'toriola333@gmail.com',
            'password': 'D3m1lad3!!'
        }
        
        response = session.post(
            f'{API_BASE_URL}/api/admin/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Session admin login response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Session admin login successful")
            
            # Now test admin stats with session (should fail because it requires Firebase)
            stats_response = session.get(f'{API_BASE_URL}/api/admin/stats')
            print(f"Admin stats with session: {stats_response.status_code}")
            if stats_response.status_code == 401:
                print("✓ Correctly requires Firebase authentication, not session")
            else:
                print(f"⚠️  WARNING: Session authentication is working for Firebase endpoint!")
                print(f"Response: {stats_response.text[:200]}...")
        else:
            print(f"✗ Session admin login failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing session vs Firebase: {e}")

def test_decorator_order():
    """Test if decorator order is causing issues"""
    try:
        print("\nTesting decorator order and implementation...")
        
        # Test with explicit headers to see what's happening
        session = requests.Session()
        
        # Login with session
        login_data = {
            'email': 'toriola333@gmail.com',
            'password': 'D3m1lad3!!'
        }
        
        response = session.post(
            f'{API_BASE_URL}/api/admin/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print("✓ Session login successful")
            
            # Test with explicit Authorization header (should fail)
            stats_response = session.get(
                f'{API_BASE_URL}/api/admin/stats',
                headers={'Authorization': 'Bearer invalid-token'}
            )
            print(f"Admin stats with invalid Firebase token: {stats_response.status_code}")
            
            # Test without Authorization header (should fail)
            stats_response2 = session.get(f'{API_BASE_URL}/api/admin/stats')
            print(f"Admin stats without Authorization header: {stats_response2.status_code}")
            
            if stats_response2.status_code == 401:
                print("✓ Correctly requires Firebase authentication")
            else:
                print(f"⚠️  WARNING: Session authentication is bypassing Firebase requirement!")
                
        else:
            print(f"✗ Session login failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing decorator order: {e}")

if __name__ == '__main__':
    test_firebase_admin_auth()
    test_session_vs_firebase()
    test_decorator_order() 