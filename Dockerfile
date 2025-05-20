FROM python:3.11-slim-bullseye

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nmap \
    git \
    python3-pip \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Create logs and scan_reports directories with proper permissions
RUN mkdir -p /toolbox/logs /app/scan_reports && chmod 777 /toolbox/logs /app/scan_reports

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /src

# Set environment variables
ENV FLASK_APP=toolbox.app
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/src

EXPOSE 5000

CMD ["flask", "run"]
