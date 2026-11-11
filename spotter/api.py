"""JSON API used by the pages, plus the network map upload."""
from flask import Blueprint, jsonify, redirect, request, url_for

from . import storage

bp = Blueprint('api', __name__, url_prefix='/api')


def _json_object():
    """The request body as a JSON object, or None if it isn't one."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


@bp.get('/data')
def get_data():
    return jsonify(storage.load_data())


@bp.post('/data')
def update_data():
    data = _json_object()
    if data is None:
        return jsonify({"success": False, "error": "Expected a JSON object"}), 400
    storage.save_data(data)
    return jsonify({"success": True})


@bp.get('/campaign')
def get_campaign():
    return jsonify(storage.load_campaign())


@bp.post('/campaign')
def update_campaign():
    campaign = _json_object()
    if campaign is None:
        return jsonify({"success": False, "error": "Expected a JSON object"}), 400
    storage.save_campaign(campaign)
    return jsonify({"success": True})


@bp.get('/iocs')
def iocs():
    """All indicators of compromise for the current operation."""
    data = storage.load_data()
    return jsonify({
        "ips": data["suspicious_ips"],
        "domains": data["phishing_domains"],
        "hashes": data["file_hashes"],
    })


@bp.get('/stats')
def stats():
    return jsonify(storage.compute_stats(storage.load_data()))


@bp.post('/upload-map')
def upload_map():
    file = request.files.get('file')
    if file is None or file.filename == '':
        return redirect(url_for('pages.network_map', error='no_file'))
    if not file.filename.lower().endswith('.xml'):
        return redirect(url_for('pages.network_map', error='invalid_type'))
    file.save(storage.network_map_path())
    return redirect(url_for('pages.network_map', success=1))
