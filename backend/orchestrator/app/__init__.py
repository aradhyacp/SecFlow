"""
Flask application factory for the SecFlow Orchestrator service.
"""

import logging
import os

from flask import Flask
from flask_cors import CORS


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, origins="*")

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(name)s — %(message)s",
    )

    from app.routes import bp
    app.register_blueprint(bp)

    return app
