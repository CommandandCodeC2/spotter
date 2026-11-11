"""Reading and writing an operation's data.

An operation lives in two JSON files in the data directory:
  data.json      incident data (timeline, IOCs, reports, storyboard, ...)
  campaign.json  operation settings (name, team, labels, kill chain)
Both are created on first run and are never committed to git.
"""
import copy
import json
import os

from flask import current_app

# Empty structure for a new incident. Real incident content lives in data.json.
DEFAULT_DATA = {
    "timeline": [],
    "suspicious_ips": [],
    "phishing_domains": [],
    "file_hashes": [],
    "threat_intel": [],
    "recommendations": [],
    "compromised_users": [],
    "affected_systems": [],
    "reports": [],
    "storyboard": []
}

# Starting settings for a new operation. campaign.json is created from this on first run.
DEFAULT_CAMPAIGN = {
    "operation_name": "New Operation",
    "subtitle": "Incident Response",
    "description": "",
    "team": {"name": "", "description": "", "members": []},
    "dashboard_title": "THREAT HUNT DASHBOARD",
    "status": "ACTIVE",
    "stats": {
        "ioc_label": "Active IOCs",
        "users_label": "Compromised Users",
        "systems_label": "Affected Systems",
        "mitre_label": "MITRE Techs",
        "status_label": "Status"
    },
    "alert_banner": {"title": "", "message": ""},
    "kill_chain_title": "ATTACK CHAIN",
    "kill_chain_phases": [
        {"name": name, "status": ""} for name in [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]
    ],
    "panels": {
        "suspicious_ips_title": "SUSPICIOUS IPS",
        "phishing_domains_title": "PHISHING & C2 DOMAINS"
    },
    "threat_intel_title": "THREAT INTELLIGENCE - EXPECTED NEXT MOVES",
    "recommendations_title": "RECOMMENDED ACTIONS"
}


def data_path():
    return os.path.join(current_app.config['DATA_DIR'], 'data.json')


def campaign_path():
    return os.path.join(current_app.config['DATA_DIR'], 'campaign.json')


def upload_dir():
    return os.path.join(current_app.config['DATA_DIR'], 'uploads')


def network_map_path():
    return os.path.join(upload_dir(), 'network_map.xml')


def _write_json(path, value):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)


def _read_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            value = json.load(f)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError) as e:
        print(f"Warning: could not read {path}: {e}")
        return {}


def ensure_data_files():
    """Create the uploads folder, and empty data.json / campaign.json on first run."""
    os.makedirs(upload_dir(), exist_ok=True)
    for path, default in ((data_path(), DEFAULT_DATA), (campaign_path(), DEFAULT_CAMPAIGN)):
        if not os.path.exists(path):
            _write_json(path, default)
            print(f"Created {os.path.basename(path)} for a new operation")


def load_data():
    data = _read_json(data_path())
    # Fill in any sections missing from data.json so every page has a list to work with.
    for key, empty in DEFAULT_DATA.items():
        data.setdefault(key, list(empty))
    return data


def save_data(data):
    _write_json(data_path(), data)


def load_campaign():
    campaign = _read_json(campaign_path())
    # Fill in anything missing so every heading and label has a value.
    for key, default in DEFAULT_CAMPAIGN.items():
        if key not in campaign:
            campaign[key] = copy.deepcopy(default)
        elif isinstance(default, dict) and isinstance(campaign[key], dict):
            for sub, value in default.items():
                campaign[key].setdefault(sub, copy.deepcopy(value))
    return campaign


def save_campaign(campaign):
    _write_json(campaign_path(), campaign)


def compute_stats(data):
    """Headline numbers for the dashboard, counted from the incident data."""
    techniques = {e.get("tech") for e in data["timeline"] if e.get("tech")}
    return {
        "active_iocs": len(data["suspicious_ips"]) + len(data["phishing_domains"]) + len(data["file_hashes"]),
        "compromised_users": len(data["compromised_users"]),
        "affected_systems": len(data["affected_systems"]),
        "mitre_techniques": len(techniques),
        "reports": len(data["reports"]),
        "timeline_events": len(data["timeline"]),
        "status": load_campaign().get("status", "")
    }
