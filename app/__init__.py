import logging

from flask import Flask, jsonify

from .config import load_settings
from .models import db


def create_app(settings=None):
    settings = settings or load_settings()
    app = Flask(__name__)
    app.config["SETTINGS"] = settings
    app.config["SQLALCHEMY_DATABASE_URI"] = settings.database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(500)
    def server_error(_):
        logging.getLogger(__name__).exception("unhandled error")
        return jsonify(error="internal error"), 500

    return app
