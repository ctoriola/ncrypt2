#!/usr/bin/env python3
"""
Test script to check if the persistent stats endpoints are working properly
"""

import requests
import json
import time

# API base URL
API_BASE_URL = 'https://web-production-5d61.up.railway.app'

def test_persistent_stats():
    """Test persistent stats functionality"""
    try:
        print("Testing persistent stats functionality...")
        
        # Test registration tracking
        registration_data = {
            'user_id': 'persistent_test_user',
            'email': 'persistent@example.com'
        }
        
        response = requests.post(
            f'{API_BASE_URL}/api/user/register',
            json=registration_data,
            headers={'Content-Type': 'application/json'}
        )
        print(f"Registration tracking response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Registration tracking successful!")
        else:
            print(f"✗ Registration tracking failed: {response.text}")
        
        # Test login tracking
        login_data = {
            'user_id': 'persistent_test_user',
            'email': 'persistent@example.com'
        }
        
        response = requests.post(
            f'{API_BASE_URL}/api/user/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        print(f"Login tracking response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Login tracking successful!")
        else:
            print(f"✗ Login tracking failed: {response.text}")
        
        # Test logout tracking
        response = requests.post(
            f'{API_BASE_URL}/api/user/logout',
            headers={'Content-Type': 'application/json'}
        )
        print(f"Logout tracking response: {response.status_code}")
        if response.status_code == 200:
            print("✓ Logout tracking successful!")
        else:
            print(f"✗ Logout tracking failed: {response.text}")
            
    except Exception as e:
        print(f"Error testing persistent stats: {e}")

def test_admin_stats_access():
    """Test if we can access admin stats (this will fail without auth, but we can see the error)"""
    try:
        response = requests.get(f'{API_BASE_URL}/api/admin/stats')
        print(f"Admin stats response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Admin stats accessible!")
            print(f"Stats: {json.dumps(data, indent=2)}")
        else:
            print(f"Admin stats error: {response.text}")
    except Exception as e:
        print(f"Error testing admin stats: {e}")

def test_multiple_registrations():
    """Test multiple user registrations to see if stats increment"""
    try:
        print("\nTesting multiple user registrations...")
        
        for i in range(1, 4):
            registration_data = {
                'user_id': f'multi_test_user_{i}',
                'email': f'multi{i}@example.com'
            }
            
            response = requests.post(
                f'{API_BASE_URL}/api/user/register',
                json=registration_data,
                headers={'Content-Type': 'application/json'}
            )
            print(f"Registration {i} response: {response.status_code}")
            if response.status_code == 200:
                print(f"✓ Registration {i} successful!")
            else:
                print(f"✗ Registration {i} failed: {response.text}")
                
    except Exception as e:
        print(f"Error testing multiple registrations: {e}")

if __name__ == '__main__':
    print("Testing persistent stats endpoints...")
    test_persistent_stats()
    print("\n" + "="*50 + "\n")
    
    print("Testing multiple registrations...")
    test_multiple_registrations()
    print("\n" + "="*50 + "\n")
    
    print("Testing admin stats access...")
    test_admin_stats_access() 