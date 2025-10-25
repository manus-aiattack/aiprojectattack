FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN groupadd -r dlnk && useradd -r -g dlnk dlnk

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    postgresql-client \
    git \
    curl \
    wget \
    nmap \
    sqlmap \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better caching
COPY requirements-production.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-production.txt

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/workspace/loot/exfiltrated \
    && mkdir -p /app/logs \
    && mkdir -p /app/data \
    && mkdir -p /app/reports \
    && chown -R dlnk:dlnk /app \
    && chmod -R 755 /app/workspace \
    && chmod -R 755 /app/logs \
    && chmod -R 755 /app/data \
    && chmod -R 755 /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO
ENV PYTHONPATH=/app
ENV SIMULATION_MODE=False

# Switch to non-root user
USER dlnk

# Expose ports
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Default command
CMD ["python", "api/main.py"]

