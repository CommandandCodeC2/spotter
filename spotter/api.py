"""JSON API used by the pages, plus the network map upload."""
import re

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


TIME_RE = re.compile(r'^(TBD|(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC) ([1-9]|[12]\d|3[01])( ([01]\d|2[0-3]):[0-5]\d)?)$')
TECH_RE = re.compile(r'^T\d{4}(\.\d{3})?$')
TACTIC_RE = re.compile(r'^\[TA\d{4}\]$')
SEVERITIES = ('critical', 'high', 'medium', 'low')


def _clean_event(body):
    """Validate a new timeline event. Returns (event, None) or (None, error message)."""
    def text(key, limit):
        value = body.get(key, '')
        return value.strip()[:limit] if isinstance(value, str) else ''

    event = {
        "time": text('time', 20).upper() or 'TBD',
        "title": text('title', 200),
        "tech": text('tech', 20).upper(),
        "tactics": text('tactics', 20).upper(),
        "desc": text('desc', 2000),
        "impact": text('impact', 300),
        "severity": text('severity', 10).lower(),
    }
    if not event["title"]:
        return None, "A title is required"
    if not TIME_RE.match(event["time"]):
        return None, "Time must look like 'NOV 11 14:05' (UTC) or 'TBD'"
    if event["tech"] and not TECH_RE.match(event["tech"]):
        return None, "Technique must look like T1059 or T1059.001"
    if event["tactics"] and not TACTIC_RE.match(event["tactics"]):
        return None, "Tactic must look like [TA0006]"
    if event["severity"] not in SEVERITIES:
        return None, "Severity must be critical, high, medium or low"
    logged_by = text('logged_by', 60)
    if logged_by:
        event["logged_by"] = logged_by
    if body.get('confirmed') is False:
        event["confirmed"] = False
    return event, None


@bp.post('/timeline')
def add_timeline_event():
    """Add one event to the timeline, without resending the whole operation."""
    body = _json_object()
    if body is None:
        return jsonify({"success": False, "error": "Expected a JSON object"}), 400
    event, error = _clean_event(body)
    if error:
        return jsonify({"success": False, "error": error}), 400
    data = storage.load_data()
    data["timeline"].append(event)
    storage.save_data(data)
    return jsonify({"success": True, "index": len(data["timeline"]) - 1, "event": event}), 201


@bp.delete('/timeline/<int:index>')
def delete_timeline_event(index):
    """Remove one event (used by Undo). The request must name the event's title
    and time, so a timeline that changed meanwhile never loses the wrong event."""
    body = _json_object() or {}
    data = storage.load_data()
    timeline = data["timeline"]
    if not 0 <= index < len(timeline) or not isinstance(timeline[index], dict):
        return jsonify({"success": False, "error": "No such event"}), 404
    event = timeline[index]
    if event.get("title") != body.get("title") or event.get("time") != body.get("time"):
        return jsonify({"success": False, "error": "The timeline changed; reload and try again"}), 409
    del timeline[index]
    storage.save_data(data)
    return jsonify({"success": True})


@bp.post('/recommendations/<int:index>')
def update_recommendation(index):
    """Mark one recommendation done or open, without resending the whole operation.

    The request includes the item's text, so a list that changed underneath
    the user (an item added, removed or reordered) is refused instead of
    updating the wrong item.
    """
    body = _json_object()
    if body is None or body.get("status") not in ("active", "completed"):
        return jsonify({"success": False, "error": "status must be 'active' or 'completed'"}), 400
    data = storage.load_data()
    recs = data["recommendations"]
    if not 0 <= index < len(recs) or not isinstance(recs[index], dict):
        return jsonify({"success": False, "error": "No such recommendation"}), 404
    if "text" in body and recs[index].get("text") != body["text"]:
        return jsonify({"success": False, "error": "The recommendations changed; reload and try again"}), 409
    recs[index]["status"] = body["status"]
    storage.save_data(data)
    return jsonify({"success": True, "recommendation": recs[index]})


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
