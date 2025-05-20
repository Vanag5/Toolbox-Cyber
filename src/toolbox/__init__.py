from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object('toolbox.config.Config')
    
    # Initialize extensions
    try:
        db.init_app(app)
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
    migrate.init_app(app, db)
    
    # Import and register blueprints
    from .routes import main_bp, scan_bp, report_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp, url_prefix='/scan')
    app.register_blueprint(report_bp, url_prefix='/report')
    
    return app