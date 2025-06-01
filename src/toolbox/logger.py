import logging
import logging.handlers
import json
from datetime import datetime
import os
from typing import Dict, Any, Optional
from pathlib import Path


class PentestLogger:
    """
    Centralized logging system for the pentest toolbox
    Handles different types of logs with proper formatting and rotation
    """

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True, parents=True)
        os.chmod(self.log_dir, 0o777)  # Ensure full read/write permissions

        # Create different log files for different purposes
        self.loggers = {
            'security': self._setup_logger('security', 'security.log'),
            'scan': self._setup_logger('scan', 'scans.log'),
            'error': self._setup_logger('error', 'error.log'),
            'access': self._setup_logger('access', 'access.log'),
            'audit': self._setup_logger('audit', 'audit.log'),
            'debug': self._setup_logger('debug', 'debug.log')
        }

        # Initialize debug log file and mode
        self.debug_log_file = self.log_dir / 'debug.log'
        self.debug_mode = False

    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        """Setup individual logger with proper formatting and rotation"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        # Create rotating file handler
        log_file = self.log_dir / filename
        open(log_file, 'a').close()
        os.chmod(log_file, 0o666)

        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )

        # Create formatters and add it to handlers
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(log_format, date_format)
        handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(handler)
        return logger

    def log_scan(self, scan_type: str, target: str, results: Dict[str, Any]) -> None:
        """Log scan results"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'scan_type': scan_type,
            'target': target,
            'results': results
        }
        self.loggers['scan'].info(json.dumps(log_entry))
        self.loggers['debug'].debug(f"Scan {scan_type} for {target} completed")

    def log_security_event(self, event_type: str, source_ip: str, details: Dict[str, Any]) -> None:
        """Log security-related events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'source_ip': source_ip,
            'details': details
        }
        self.loggers['security'].warning(json.dumps(log_entry))
        self.loggers['debug'].debug(
            f"Security event {event_type} from {source_ip} detected")

    def log_error(self, error_type: str, error_message: str, stack_trace: Optional[str] = None) -> None:
        """Log error events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'error_type': error_type,
            'error_message': error_message,
            'stack_trace': stack_trace
        }
        self.loggers['error'].error(json.dumps(log_entry))
        self.loggers['debug'].debug(
            f"Error {error_type} occurred: {error_message}")

    def log_access(self, request_method: str, endpoint: str, source_ip: str,
                   status_code: int, response_time: float) -> None:
        """Log API access"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'method': request_method,
            'endpoint': endpoint,
            'source_ip': source_ip,
            'status_code': status_code,
            'response_time': response_time
        }
        self.loggers['access'].info(json.dumps(log_entry))
        self.loggers['debug'].debug(
            f"Access log: {request_method} {endpoint} from {source_ip}")

    def log_audit(self, user: str, action: str, resource: str, status: str) -> None:
        """Log audit events for compliance and tracking"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'action': action,
            'resource': resource,
            'status': status
        }
        self.loggers['audit'].info(json.dumps(log_entry))
        self.loggers['debug'].debug(f"Audit log: {user} {action} {resource}")

    def log_debug(self, message, **kwargs):
        """
        Log a debug message with optional additional context

        :param message: Debug message to log
        :param kwargs: Additional context information to log
        """
        # Prepare log entry
        log_entry = {
            'level': 'DEBUG',
            'message': message,
        }

        # Add any additional context
        if kwargs:
            log_entry['context'] = kwargs

        # Log to file
        try:
            with open(self.debug_log_file, 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            # Fallback to standard print if file logging fails
            print(f"DEBUG LOG ERROR: {e}")
            print(json.dumps(log_entry))

        # Optional: also log to console if in debug mode
        if self.debug_mode:
            print(f"DEBUG: {message}")
            if kwargs:
                print(f"CONTEXT: {json.dumps(kwargs, indent=2)}")

    def get_recent_logs(self, log_type: str, limit: int = 100) -> list:
        """Retrieve recent logs of specified type"""
        try:
            log_file = self.log_dir / f"{log_type}.log"
            if not log_file.exists():
                return []

            with open(log_file, 'r') as f:
                # Read last 'limit' lines
                lines = f.readlines()[-limit:]
                return [json.loads(line.split(' - ')[-1]) for line in lines]
        except Exception as e:
            self.log_error('log_retrieval_error', str(e))
            return []

    def error(self, msg: str, *args, **kwargs):
        self.loggers['error'].error(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self.loggers['debug'].info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.loggers['debug'].warning(msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs):
        self.loggers['debug'].debug(msg, *args, **kwargs)    


# Initialize global logger instance
logger = PentestLogger()
