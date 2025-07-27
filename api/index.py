"""
Vercel serverless function entry point for NCryp Flask backend
"""
import sys
import os

# Add the parent directory to the Python path so we can import server
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app

# Vercel expects a handler function
def handler(request, context):
    return app(request.environ, context)

# For Vercel's WSGI compatibility
application = app

# This is the entry point that Vercel will use
if __name__ == "__main__":
    app.run()
