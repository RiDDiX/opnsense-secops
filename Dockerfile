FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create output directory
RUN mkdir -p /app/reports

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.main"]
