import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-this')

    # SQLAlchemy Configuration (chemin absolu vers la base SQLite)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f"sqlite:///{os.path.join(basedir, '../pentest_toolbox.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Logging Configuration
    LOG_DIR = os.path.join(basedir, '../logs')

    # Security Configuration
    SCAN_RATE_LIMIT = int(
        os.getenv('SCAN_RATE_LIMIT', '10'))  # scans per minute
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))

    # Scan Timeouts (in seconds)
    VULNERABILITY_SCAN_TIMEOUT = int(
        os.getenv('VULNERABILITY_SCAN_TIMEOUT', '3600'))  # 1 hour
    PORT_SCAN_TIMEOUT = int(os.getenv('PORT_SCAN_TIMEOUT', '300'))  # 5 minutes

    # API Configuration
    API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', '100')
                         )  # requests per minute

    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'