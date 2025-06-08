FROM python:3.11-slim-bullseye

# Install system dependencies and OWASP ZAP in a single RUN to avoid cache issues
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nmap \
    git \
    python3-pip \
    perl \
    build-essential \
    libssl-dev \
    libssh-dev \
    libidn11-dev \
    libpcre3-dev \
    libgtk2.0-dev \
    libpq-dev \
    libmariadb-dev-compat \
    libsvn-dev \
    firebird-dev \
    libmemcached-dev \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    gcc \
    wget \
    openjdk-17-jre && \
    # Download and verify OWASP ZAP 2.16.1
    wget -O /tmp/ZAP_2.16.1_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz && \
    echo "5b2eb8319b085121a6e8ad50d69d67dbef8c867166f71a937bfc888d247a2ac1 /tmp/ZAP_2.16.1_Linux.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/ZAP_2.16.1_Linux.tar.gz -C /opt && \
    ln -s /opt/ZAP_2.16.1/zap.sh /usr/local/bin/zap && \
    # rm -f /tmp/ZAP_2.16.1
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone sqlmap manually
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

ENV PATH="/opt/sqlmap:$PATH"

WORKDIR /src

# Clone and build Hydra
RUN git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/hydra && \
    cd /opt/hydra && \
    ./configure && \
    make && \
    make install

# Create logs and scan_reports directories with proper permissions
RUN mkdir -p /toolbox/logs /app/scan_reports && chmod 777 /toolbox/logs /app/scan_reports

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /src

# Set environment variables
ENV FLASK_APP=toolbox.app
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/src

EXPOSE 5000

# Default command
CMD ["flask", "run"]