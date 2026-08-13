import os
import sys
from flask import Flask

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SECRET_KEY, FLASK_DEBUG
from database.db import init_db

def create_app():
    """
    Flask Application Factory
    Initializes SQLite database and registers web dashboard blueprints.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = FLASK_DEBUG

    # Initialize Database Tables
    init_db()

    # Register Dashboard Routes Blueprint
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    return app
