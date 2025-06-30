#!/usr/bin/env python3
"""
Test script to verify frontend admin dashboard with local backend
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"
FRONTEND_URL = "http://localhost:5173"

def test_frontend_connection():
    """Test if frontend is accessible"""
    try:
        response = requests.get(FRONTEND_URL, timeout=5)
        print(f"Frontend Status: {response.status_code}")
        if response.status_code == 200:
            print("✅ Frontend is accessible!")
            return True
        else:
            print("❌ Frontend returned non-200 status")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Frontend connection failed: {e}")
        return False

def test_backend_connection():
    """Test if backend is accessible"""
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        print(f"Backend Status: {response.status_code}")
        if response.status_code == 200:
            print("✅ Backend is accessible!")
            return True
        else:
            print("❌ Backend returned non-200 status")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Backend connection failed: {e}")
        return False

def test_admin_workflow():
    """Test complete admin workflow"""
    print("\nTesting admin workflow...")
    
    # Test login
    login_data = {
        "username": "admin",
        "password": "ub#49*KTvKAa"
    }
    
    session = requests.Session()
    
    try:
        # Login
        login_response = session.post(
            f"{BASE_URL}/api/admin/login",
            json=login_data,
            headers={"Content-Type": "application/json"}
        )
        
        if login_response.status_code == 200:
            print("✅ Admin login successful")
            
            # Test stats
            stats_response = session.get(f"{BASE_URL}/api/admin/stats")
            if stats_response.status_code == 200:
                print("✅ Admin stats accessible")
                stats_data = stats_response.json()
                print(f"   - Total visits: {stats_data.get('total_visits', 0)}")
                print(f"   - Unique visitors: {stats_data.get('unique_visitors', 0)}")
            else:
                print(f"❌ Admin stats failed: {stats_response.status_code}")
            
            # Test files
            files_response = session.get(f"{BASE_URL}/api/admin/files")
            if files_response.status_code == 200:
                print("✅ Admin files accessible")
                files_data = files_response.json()
                print(f"   - Total files: {len(files_data.get('files', []))}")
            else:
                print(f"❌ Admin files failed: {files_response.status_code}")
            
            # Logout
            logout_response = session.post(f"{BASE_URL}/api/admin/logout")
            if logout_response.status_code == 200:
                print("✅ Admin logout successful")
            else:
                print(f"❌ Admin logout failed: {logout_response.status_code}")
                
        else:
            print(f"❌ Admin login failed: {login_response.status_code}")
            print(f"   Response: {login_response.text}")
            
    except Exception as e:
        print(f"❌ Admin workflow error: {e}")

def main():
    print("NCryp Frontend Admin Dashboard Test")
    print("=" * 50)
    
    # Test connections
    frontend_ok = test_frontend_connection()
    backend_ok = test_backend_connection()
    
    if frontend_ok and backend_ok:
        print("\n✅ Both frontend and backend are running!")
        test_admin_workflow()
        
        print("\n" + "=" * 50)
        print("🎉 Setup Instructions:")
        print("1. Open your browser and go to: http://localhost:5173")
        print("2. Click on the 'Admin' tab")
        print("3. Login with:")
        print("   Username: admin")
        print("   Password: ub#49*KTvKAa")
        print("4. You should now see the admin dashboard with statistics!")
        
    else:
        print("\n❌ One or more services are not running properly.")
        if not backend_ok:
            print("   - Make sure the backend is running: python server.py")
        if not frontend_ok:
            print("   - Make sure the frontend is running: cd frontend && npm run dev")

if __name__ == "__main__":
    main() 