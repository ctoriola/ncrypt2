#!/usr/bin/env python3
"""
Script to simulate user activity for testing admin dashboard
"""

import requests
import time
import random

def simulate_activity():
    base_url = "http://localhost:5000"
    
    print("Simulating User Activity")
    print("=" * 40)
    
    # Simulate some page visits
    endpoints = [
        "/api/health",
        "/api/files", 
        "/api/search/ABC12345"
    ]
    
    print("1. Simulating page visits...")
    for i in range(5):
        endpoint = random.choice(endpoints)
        try:
            response = requests.get(f"{base_url}{endpoint}")
            print(f"   Visit {i+1}: {endpoint} - Status: {response.status_code}")
            time.sleep(0.5)  # Small delay between requests
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n2. Simulating file upload (mock)...")
    # Create a mock file upload to test upload stats
    mock_file_data = b"This is a test file for admin dashboard testing"
    
    try:
        # We'll simulate the upload by calling the upload endpoint with test data
        files = {'file': ('test.txt', mock_file_data, 'text/plain')}
        data = {'passphrase': 'testpassphrase123'}
        
        response = requests.post(f"{base_url}/api/upload", files=files, data=data)
        print(f"   Upload status: {response.status_code}")
        if response.status_code == 201:
            print("   ✅ Upload successful!")
            upload_data = response.json()
            print(f"   File ID: {upload_data.get('file_id')}")
            print(f"   Share ID: {upload_data.get('share_id')}")
        else:
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Upload error: {e}")
    
    print("\n3. Simulating file download...")
    try:
        # Try to download the file we just uploaded
        response = requests.get(f"{base_url}/api/files")
        if response.status_code == 200:
            files_data = response.json()
            if files_data.get('files'):
                file_id = files_data['files'][0]['id']
                download_response = requests.get(f"{base_url}/api/files/{file_id}")
                print(f"   Download status: {download_response.status_code}")
                if download_response.status_code == 200:
                    print("   ✅ Download successful!")
                else:
                    print(f"   Download response: {download_response.text}")
            else:
                print("   No files to download")
        else:
            print(f"   Error getting files: {response.text}")
    except Exception as e:
        print(f"   Download error: {e}")
    
    print("\n" + "=" * 40)
    print("Activity simulation completed!")
    print("\nNow test the admin dashboard - it should show:")
    print("- Total visits: 5+")
    print("- Unique visitors: 1")
    print("- Total uploads: 1")
    print("- Total downloads: 1")
    print("- Files in the files tab")

if __name__ == "__main__":
    simulate_activity() 