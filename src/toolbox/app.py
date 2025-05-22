import os
from flask import request, jsonify, render_template
from toolbox import create_app
print("Starting Flask application...")

app = create_app()

# Create Flask app with explicit template folder
# app = Flask(__name__,
#            template_folder=os.path.join(os.path.dirname(__file__), 'app', 'templates'),
#            static_folder=os.path.join(os.path.dirname(__file__), 'app', 'static'))

# Define Nmap scan profiles
NMAP_SCAN_PROFILES = {
    'quick': '-F -sV',  # Fast scan of common ports
    'default': '-sV -sC',  # Default scan with version detection and scripts
    'full': '-sV -sC -A -T4',  # Aggressive scan with OS detection
    'stealth': '-sS -sV -T2',  # Stealthy SYN scan
    'vuln': '-sV -sC --script=vuln',  # Vulnerability scan
    'service': '-sV -sC -p-',  # Full port range service scan
}

# In-memory storage for active scans and reports
active_scans = {}
scan_reports = {}

# Error handlers


@app.errorhandler(404)
def not_found_error(error):
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'error', 'message': 'Resource not found'}), 404
    return render_template('error.html', error={'code': 404, 'message': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    return render_template('error.html', error={'code': 500, 'message': 'Internal server error'}), 500


if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    try:
        os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    except KeyError:
        app.logger.error("LOG_DIR is not defined in the configuration.")
    except Exception as e:
        app.logger.error(f"Failed to create logs directory: {e}")
    app.run(host="0.0.0.0", port=5000, debug=True)
