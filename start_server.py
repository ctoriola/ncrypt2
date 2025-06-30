#!/usr/bin/env python3
"""
Startup script for NCryp server
This ensures proper initialization when running with gunicorn
"""

import os
import logging
from server import app

if __name__ == '__main__':
    # Configure logging
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    logging.basicConfig(level=getattr(logging, log_level.upper()))
    
    # Get port from environment (Railway sets PORT)
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logging.info(f"Starting NCryp server with port {port}")
    logging.info(f"Debug mode: {debug}")
    
    app.run(debug=debug, host=host, port=port) 