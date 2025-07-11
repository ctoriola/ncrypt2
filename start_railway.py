#!/usr/bin/env python3
"""
Railway Startup Script for NCryp
"""

import os
import sys
from server import app

if __name__ == '__main__':
    # Get port from Railway environment
    port = int(os.getenv('PORT', 5000))
    host = '0.0.0.0'
    
    print(f"Starting NCryp server on {host}:{port}")
    print(f"PORT environment: {os.getenv('PORT', 'Not set')}")
    
    # Run the Flask app
    app.run(host=host, port=port, debug=False) 