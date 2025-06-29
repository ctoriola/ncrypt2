#!/bin/bash

echo "Installing Python dependencies..."

# Try to install with --break-system-packages flag
pip install --break-system-packages -r requirements.txt

# Check if installation was successful
if [ $? -eq 0 ]; then
    echo "Dependencies installed successfully!"
else
    echo "Failed to install with --break-system-packages, trying virtual environment..."
    
    # Create virtual environment
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo "Dependencies installed in virtual environment!"
    else
        echo "Failed to install dependencies!"
        exit 1
    fi
fi 