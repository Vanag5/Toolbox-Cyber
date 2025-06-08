from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from .celery import celery, init_celery

# Initialisation des extensions globales
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
# Redirige vers /login si l'utilisateur n'est pas connecté
login_manager.login_view = 'auth.login'


def create_app():
    app = Flask(__name__)
    # Vérifie que ce chemin est correct
    app.config.from_object('toolbox.config.Config')
    print("Config keys:", app.config.keys())
    print("CELERY_BROKER_URL:", app.config.get('CELERY_BROKER_URL'))
    # Initialisation des extensions avec l'application
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Importation différée pour éviter les imports circulaires
    from .routes import main_bp, scan_bp, report_bp
    from .auth import auth_bp
    from .models import User
    from .port_scanner import PortScanner
    from .hydra_scanner import HydraScanner
    from .zap_scanner import ZAPScanner
    app.port_scanner = PortScanner(app=app)
    app.hydra_scanner = HydraScanner(app=app)
    app.zap_scanner = ZAPScanner(app=app)
    
    # Enregistrement des blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp, url_prefix='/scan')
    app.register_blueprint(report_bp, url_prefix='/report')
    app.register_blueprint(auth_bp)

    # Fonction de chargement d'un utilisateur par Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except (ValueError, TypeError):
            return None

    init_celery(app) 

    return app
