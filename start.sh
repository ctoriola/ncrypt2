#!/bin/bash

# Set default port if not provided
export PORT=${PORT:-5000}

echo "Starting NCryp server on port $PORT"

# Check if we're in a Railway environment
if [ -n "$RAILWAY_STATIC_URL" ]; then
    echo "Running in Railway environment"
    # Railway automatically sets PORT
    exec gunicorn --bind 0.0.0.0:$PORT server:app
else
    echo "Running in local environment"
    # For local development
    exec python server.py
fi

# NCryp Development Startup Script

echo "🚀 Starting NCryp Development Environment..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

# Check if env.local file exists
if [ ! -f env.local ]; then
    echo "⚠️  env.local file not found. Creating from template..."
    cp env.example env.local
    echo "📝 Please edit env.local file with your configuration before continuing."
    echo "   Required: AWS credentials, S3 bucket name (if using cloud storage)"
    read -p "Press Enter when you've configured env.local file..."
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Start backend server in background
echo "🔧 Starting Flask backend server..."
python server.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend development server
echo "🎨 Starting React development server..."
npm run dev

# Cleanup on exit
trap "echo '🛑 Shutting down...'; kill $BACKEND_PID 2>/dev/null; exit" INT TERM

# Keep script running
wait 