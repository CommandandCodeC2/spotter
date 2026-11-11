"""Spotter: the common operating picture for cyber exercises and incident response teams."""
import os

from flask import Flask

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app(data_dir=None):
    """Build the Spotter app.

    data_dir is where data.json, campaign.json and uploads/ live. It defaults to
    the SPOTTER_DATA_DIR environment variable, or the project folder.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(PROJECT_ROOT, 'templates'),
        static_folder=os.path.join(PROJECT_ROOT, 'static'),
    )
    app.config['DATA_DIR'] = os.path.abspath(
        data_dir or os.environ.get('SPOTTER_DATA_DIR') or PROJECT_ROOT
    )

    from . import api, pages, storage
    app.register_blueprint(pages.bp)
    app.register_blueprint(api.bp)

    with app.app_context():
        storage.ensure_data_files()

    return app
