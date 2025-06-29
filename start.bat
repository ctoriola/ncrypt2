@echo off
REM NCryp Development Startup Script for Windows

echo 🚀 Starting NCryp Development Environment...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.8+ first.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js is not installed. Please install Node.js 16+ first.
    pause
    exit /b 1
)

REM Check if env.local file exists
if not exist env.local (
    echo ⚠️  env.local file not found. Creating from template...
    copy env.example env.local
    echo 📝 Please edit env.local file with your configuration before continuing.
    echo    Required: AWS credentials, S3 bucket name (if using cloud storage)
    pause
)

REM Install Python dependencies
echo 📦 Installing Python dependencies...
pip install -r requirements.txt

REM Install Node.js dependencies
echo 📦 Installing Node.js dependencies...
npm install

REM Start backend server in background
echo 🔧 Starting Flask backend server...
start /B python server.py

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend development server
echo 🎨 Starting React development server...
npm run dev

pause 