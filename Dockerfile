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
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone sqlmap manually (it is not an apt package)
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

ENV PATH="/opt/sqlmap:$PATH"

WORKDIR /src

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
