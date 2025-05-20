import os

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-this')
    
    # SQLAlchemy Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///pentest_toolbox.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Logging Configuration
    LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    
    # Security Configuration
    SCAN_RATE_LIMIT = int(os.getenv('SCAN_RATE_LIMIT', '10'))  # scans per minute
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))
    
    # Scan Timeouts (in seconds)
    VULNERABILITY_SCAN_TIMEOUT = int(os.getenv('VULNERABILITY_SCAN_TIMEOUT', '3600'))  # 1 hour
    PORT_SCAN_TIMEOUT = int(os.getenv('PORT_SCAN_TIMEOUT', '300'))  # 5 minutes
    
    # API Configuration
    API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', '100'))  # requests per minute
