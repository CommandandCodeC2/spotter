"""Start Spotter.

    python3 server.py

Settings (environment variables):
    PORT              port to listen on (default 8089)
    HOST              address to listen on (default 0.0.0.0, all interfaces)
    SPOTTER_DATA_DIR  folder for data.json, campaign.json and uploads/ (default: this folder)
"""
import os

from spotter import create_app
from spotter.storage import load_campaign

app = create_app()


def main():
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8089))
    with app.app_context():
        name = load_campaign().get('operation_name') or 'New Operation'

    print("=" * 50)
    print("SPOTTER  |  " + name)
    print(f"Running on http://{host}:{port}")
    print("=" * 50, flush=True)

    try:
        from waitress import serve
    except ImportError:
        print("Waitress is not installed, so using Flask's development server.")
        print("Install it with: pip install -r requirements.txt", flush=True)
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    else:
        serve(app, host=host, port=port, threads=8)


if __name__ == '__main__':
    main()
