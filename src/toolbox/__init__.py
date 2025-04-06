__version__ = "0.1.0"
from flask import Flask
import os

def create_app():
    app = Flask(__name__, template_folder=os.path.abspath('toolbox/templates'))
    app.config['SESSION_TYPE'] = 'filesystem'

    # Import et enregistrement des routes
    app.register_blueprint(routes)

return app
