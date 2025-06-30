FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose port (will be overridden by Railway)
EXPOSE 5000

# Start the application using Railway's PORT environment variable
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "1", "server:app"] 