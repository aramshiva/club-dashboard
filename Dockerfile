FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create uploads directory with proper permissions
RUN mkdir -p static/uploads && \
    chmod 755 static/uploads

# Create a non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app && \
    chown -R appuser:appuser static/uploads

# Switch to non-root user
USER appuser

# Use the PORT environment variable or default to 5000
EXPOSE ${PORT:-5000}

# Security-focused environment variables
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Use gunicorn configuration file for better security
CMD ["gunicorn", "-c", "gunicorn.conf.py", "main:app"]