#!/bin/bash

echo "Building frontend only..."

# Install Node.js dependencies
npm install

# Build the frontend
npm run build

echo "Frontend build complete!" 