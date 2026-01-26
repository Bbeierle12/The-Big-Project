FROM python:3.12-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tshark \
    clamav \
    fail2ban \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application
COPY config/ ./config/
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini ./

# Create non-root user
RUN useradd -m -s /bin/bash netsec
USER netsec

EXPOSE 8420

CMD ["python", "-m", "netsec"]
