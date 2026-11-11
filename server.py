from flask import Flask, send_file, jsonify, request, render_template_string
from flask_cors import CORS
import os
import json
import xml.etree.ElementTree as ET
import uuid

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(__file__)
DASHBOARD_PATH = os.path.join(BASE_DIR, 'dashboard.html')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DATA_FILE = os.path.join(BASE_DIR, 'data.json')
CAMPAIGN_FILE = os.path.join(BASE_DIR, 'campaign.json')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

def ensure_data_files():
    """Create empty data.json and campaign.json the first time the dashboard runs.

    These files hold the user's own mission data and are not stored in git.
    """
    for path, default in ((DATA_FILE, DEFAULT_DATA), (CAMPAIGN_FILE, DEFAULT_CAMPAIGN)):
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(default, f, indent=2, ensure_ascii=False)
            print(f"Created {os.path.basename(path)} for a new operation")

def load_data():
    data = {}
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Warning: could not read {DATA_FILE}: {e}")
    # Fill in any sections missing from data.json so every page has a list to work with.
    for key, empty in DEFAULT_DATA.items():
        data.setdefault(key, list(empty))
    return data

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_campaign():
    campaign = {}
    if os.path.exists(CAMPAIGN_FILE):
        try:
            with open(CAMPAIGN_FILE, 'r', encoding='utf-8') as f:
                campaign = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Warning: could not read {CAMPAIGN_FILE}: {e}")
    # Fill in anything missing so every heading and label has a value.
    for key, default in DEFAULT_CAMPAIGN.items():
        if key not in campaign:
            campaign[key] = json.loads(json.dumps(default))
        elif isinstance(default, dict) and isinstance(campaign[key], dict):
            for sub, value in default.items():
                campaign[key].setdefault(sub, value)
    return campaign

def save_campaign(data):
    with open(CAMPAIGN_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

ensure_data_files()

@app.route('/api/data')
def get_data():
    return jsonify(load_data())

@app.route('/api/data', methods=['POST'])
def update_data():
    data = request.json
    save_data(data)
    return jsonify({"success": True})

@app.route('/api/campaign')
def get_campaign():
    return jsonify(load_campaign())

@app.route('/api/campaign', methods=['POST'])
def update_campaign():
    data = request.json
    save_campaign(data)
    return jsonify({"success": True})

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin · Spotter</title>
    <link rel="icon" type="image/svg+xml" href="/static/logo.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/brand.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        .container { padding: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
        .card h2 { color: var(--text-strong); font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .card h2 .count { background: var(--accent-soft); color: var(--accent); padding: 2px 10px; border-radius: 10px; font-size: 12px; font-family: var(--font-mono); letter-spacing: 0; }
        .item { background: var(--surface-0); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 10px; position: relative; }
        .item:hover { border-color: var(--accent); }
        .item-row { display: flex; gap: 10px; margin-bottom: 8px; }
        .item-row label { min-width: 80px; color: var(--text-muted); font-size: 12px; padding-top: 8px; }
        .item-row input, .item-row select { flex: 1; background: var(--surface-2); border: 1px solid var(--border); color: var(--text); padding: 8px; border-radius: 4px; font-size: 13px; }
        .item-row input:focus { outline: none; border-color: var(--accent); }
        .btn { background: var(--accent); color: var(--on-accent); padding: 8px 16px; border: 1px solid transparent; border-radius: var(--radius); font-weight: 600; cursor: pointer; font-size: 12px; transition: background 0.15s, color 0.15s, border-color 0.15s; }
        .btn:hover { background: var(--accent-hover); }
        .btn.add { background: transparent; color: var(--accent); border-color: var(--accent); }
        .btn.add:hover { background: var(--accent-soft); }
        .btn.delete { background: transparent; color: var(--text-muted); border-color: var(--border-strong); padding: 4px 10px; }
        .btn.delete:hover { background: var(--critical-soft); color: var(--critical); border-color: var(--critical); }
        .btn.save { width: 100%; padding: 12px; font-size: 14px; margin-top: 20px; }
        .empty { color: var(--text-muted); text-align: center; padding: 20px; font-style: italic; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; }
        .nav a { color: var(--accent); text-decoration: none; padding: 10px 20px; background: var(--surface-1); border-radius: 5px; }
        .nav a:hover { background: var(--accent-soft); }
    </style>
</head>
<body>
    <nav class="sidebar" id="app-nav" data-active="admin"></nav>
    <script src="/static/brand.js"></script>
    <div class="main-content">
    <div class="header">
        <h1>Admin <span class="op-name" id="adminOpName"></span></h1>
    </div>
    <div class="container">
        <div class="card" style="grid-column: 1 / -1;">
            <h2>Campaign Settings</h2>
            <div class="item">
                <div class="item-row"><label>Operation</label><input id="cfgOpName" placeholder="Operation name"></div>
                <div class="item-row"><label>Subtitle</label><input id="cfgSubtitle" placeholder="Subtitle"></div>
                <div class="item-row"><label>Description</label><input id="cfgDesc" placeholder="Campaign description"></div>
                <div class="item-row"><label>Status</label><input id="cfgStatus" placeholder="HUNTING / CONTAINED / CLOSED"></div>
            </div>
        </div>

        <div class="card">
            <h2>Suspicious IPs <span class="count" id="ipCount">0</span></h2>
            <div id="ipList"></div>
            <button class="btn add" onclick="addIP()">+ Add IP</button>
        </div>
        
        <div class="card">
            <h2>Phishing Domains <span class="count" id="domainCount">0</span></h2>
            <div id="domainList"></div>
            <button class="btn add" onclick="addDomain()">+ Add Domain</button>
        </div>
        
        <div class="card">
            <h2>Timeline Events <span class="count" id="timelineCount">0</span></h2>
            <div id="timelineList"></div>
            <button class="btn add" onclick="addTimeline()">+ Add Event</button>
        </div>
        
        <div class="card">
            <h2>Recommendations <span class="count" id="recCount">0</span></h2>
            <div id="recList"></div>
            <button class="btn add" onclick="addRec()">+ Add Recommendation</button>
        </div>
    </div>
    <div class="container">
        <button class="btn save" onclick="saveAll()">Save all changes</button>
    </div>
    
    <script>
        let data = null;
        let campaign = null;

        function loadAll() {
            Promise.all([
                fetch('/api/data').then(r => r.json()),
                fetch('/api/campaign').then(r => r.json())
            ]).then(([d, c]) => {
                data = d;
                campaign = c;
                renderCampaign(c);
                renderAll();
            });
        }

        function renderCampaign(c) {
            document.getElementById('adminOpName').textContent = c.operation_name || '';
            document.getElementById('cfgOpName').value = c.operation_name || '';
            document.getElementById('cfgSubtitle').value = c.subtitle || '';
            document.getElementById('cfgDesc').value = c.description || '';
            document.getElementById('cfgStatus').value = c.status || '';
        }

        function saveCampaign() {
            return {
                ...campaign,
                operation_name: document.getElementById('cfgOpName').value,
                subtitle: document.getElementById('cfgSubtitle').value,
                description: document.getElementById('cfgDesc').value,
                status: document.getElementById('cfgStatus').value
            };
        }

        function renderAll() {
            renderIPs();
            renderDomains();
            renderTimeline();
            renderRecs();
        }
        
        function renderIPs() {
            const list = document.getElementById('ipList');
            const ips = data.suspicious_ips || [];
            document.getElementById('ipCount').textContent = ips.length;
            if (!ips.length) { list.innerHTML = '<div class="empty">No IPs added</div>'; return; }
            list.innerHTML = ips.map((ip, i) => renderItem(ip, 'ip', i)).join('');
        }
        
        function renderDomains() {
            const list = document.getElementById('domainList');
            const domains = data.phishing_domains || [];
            document.getElementById('domainCount').textContent = domains.length;
            if (!domains.length) { list.innerHTML = '<div class="empty">No domains added</div>'; return; }
            list.innerHTML = domains.map((d, i) => renderItem(d, 'domain', i)).join('');
        }
        
        function renderTimeline() {
            const list = document.getElementById('timelineList');
            const items = data.timeline || [];
            document.getElementById('timelineCount').textContent = items.length;
            if (!items.length) { list.innerHTML = '<div class="empty">No events added</div>'; return; }
            list.innerHTML = items.map((t, i) => renderTimelineItem(t, i)).join('');
        }
        
        function renderRecs() {
            const list = document.getElementById('recList');
            const items = data.recommendations || [];
            document.getElementById('recCount').textContent = items.length;
            if (!items.length) { list.innerHTML = '<div class="empty">No recommendations</div>'; return; }
            list.innerHTML = items.map((r, i) => renderItem(r, 'rec', i)).join('');
        }
        
        function renderItem(obj, type, idx) {
            if (type === 'ip') {
                return `<div class="item">
                    <div class="item-row"><label>IP</label><input value="${obj.ip || ''}" onchange="update('suspicious_ips',${idx},'ip',this.value)"></div>
                    <div class="item-row"><label>Label</label><input value="${obj.label || ''}" onchange="update('suspicious_ips',${idx},'label',this.value)"></div>
                    <div class="item-row"><label>Type</label><input value="${obj.type || ''}" onchange="update('suspicious_ips',${idx},'type',this.value)"></div>
                    <div class="item-row"><label>Status</label><select onchange="update('suspicious_ips',${idx},'status',this.value)"><option ${obj.status==='ACTIVE'?'selected':''}>ACTIVE</option><option ${obj.status==='BLOCKED'?'selected':''}>BLOCKED</option></select></div>
                    <button class="btn delete" onclick="deleteItem('suspicious_ips',${idx})">Remove</button>
                </div>`;
            }
            if (type === 'domain') {
                return `<div class="item">
                    <div class="item-row"><label>Domain</label><input value="${obj.domain || ''}" onchange="update('phishing_domains',${idx},'domain',this.value)"></div>
                    <div class="item-row"><label>Type</label><input value="${obj.type || ''}" onchange="update('phishing_domains',${idx},'type',this.value)"></div>
                    <button class="btn delete" onclick="deleteItem('phishing_domains',${idx})">Remove</button>
                </div>`;
            }
            if (type === 'rec') {
                return `<div class="item">
                    <div class="item-row"><label>Text</label><input value="${obj.text || ''}" onchange="update('recommendations',${idx},'text',this.value)"></div>
                    <div class="item-row"><label>MITRE</label><input value="${obj.mitre || ''}" onchange="update('recommendations',${idx},'mitre',this.value)"></div>
                    <div class="item-row"><label>Status</label><select onchange="update('recommendations',${idx},'status',this.value)"><option ${obj.status==='active'?'selected':''}>active</option><option ${obj.status==='completed'?'selected':''}>completed</option></select></div>
                    <button class="btn delete" onclick="deleteItem('recommendations',${idx})">Remove</button>
                </div>`;
            }
            return '';
        }
        
        function renderTimelineItem(obj, idx) {
            const timeStr = obj.time || '';
            const dateMatch = timeStr.match(/([A-Z]+)\\s*(\\d+)/i);
            let isoDate = '';
            if (dateMatch) {
                const months = {JAN:0,FEB:1,MAR:2,APR:3,MAY:4,JUN:5,JUL:6,AUG:7,SEP:8,OCT:9,NOV:10,DEC:11};
                const mo = months[dateMatch[1].toUpperCase().slice(0,3)];
                if (mo !== undefined) {
                    const d = new Date(2026, mo, parseInt(dateMatch[2]));
                    isoDate = d.toISOString().split('T')[0];
                }
            }
            const timeOnly = timeStr.replace(/[A-Z]+\\s*\\d+\\s*/i, '').trim();
            return `<div class="item">
                <div class="item-row"><label>Date</label><input type="date" id="date_${idx}" value="${isoDate}" onchange="updateTime(${idx},this.value,document.getElementById('time_${idx}').value)" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:4px;"></div>
                <div class="item-row"><label>Time</label><input id="time_${idx}" value="${timeOnly}" onchange="updateTime(${idx},document.getElementById('date_${idx}').value,this.value)" placeholder="HH:MM"></div>
                <div class="item-row"><label>Title</label><input value="${obj.title || ''}" onchange="update('timeline',${idx},'title',this.value)"></div>
                <div class="item-row"><label>Tech</label><input value="${obj.tech || ''}" onchange="update('timeline',${idx},'tech',this.value)"></div>
                <div class="item-row"><label>Tactics</label><input value="${obj.tactics || ''}" onchange="update('timeline',${idx},'tactics',this.value)"></div>
                <div class="item-row"><label>Description</label><input value="${obj.desc || ''}" onchange="update('timeline',${idx},'desc',this.value)"></div>
                <div class="item-row"><label>Impact</label><input value="${obj.impact || ''}" onchange="update('timeline',${idx},'impact',this.value)"></div>
                <div class="item-row"><label>Severity</label><select onchange="update('timeline',${idx},'severity',this.value)"><option ${obj.severity==='critical'?'selected':''}>critical</option><option ${obj.severity==='high'?'selected':''}>high</option><option ${obj.severity==='medium'?'selected':''}>medium</option></select></div>
                <button class="btn delete" onclick="deleteItem('timeline',${idx})">Remove</button>
            </div>`;
        }
        
        function updateTime(idx, dateVal, timeVal) {
            if (!dateVal && !timeVal) return;
            let dateStr = '';
            if (dateVal) {
                const d = new Date(dateVal + 'T00:00:00');
                const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
                dateStr = months[d.getMonth()] + ' ' + d.getDate();
            }
            const newTime = timeVal ? dateStr + ' ' + timeVal : dateStr;
            data.timeline[idx].time = newTime;
        }
        
        function update(key, idx, field, value) {
            data[key][idx][field] = value;
        }
        
        function deleteItem(key, idx) {
            data[key].splice(idx, 1);
            renderAll();
        }
        
        function addIP() {
            data.suspicious_ips = data.suspicious_ips || [];
            data.suspicious_ips.push({ip: '0.0.0.0', label: '', type: 'ATTACKER', status: 'ACTIVE'});
            renderAll();
        }
        
        function addDomain() {
            data.phishing_domains = data.phishing_domains || [];
            data.phishing_domains.push({domain: 'example.com', type: 'PHISHING'});
            renderAll();
        }
        
        function addTimeline() {
            data.timeline = data.timeline || [];
            const now = new Date();
            const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
            data.timeline.push({time: months[now.getMonth()] + ' ' + now.getDate(), title: 'New Event', tech: 'T0000', tactics: '[TA0000]', desc: 'Description', impact: 'Impact', severity: 'high'});
            renderAll();
        }
        
        function addRec() {
            data.recommendations = data.recommendations || [];
            data.recommendations.push({text: 'New recommendation', mitre: 'T0000', status: 'active'});
            renderAll();
        }
        
        function saveAll() {
            const campData = saveCampaign();
            Promise.all([
                fetch('/api/data', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                }).then(r => r.json()),
                fetch('/api/campaign', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(campData)
                }).then(r => r.json())
            ]).then(() => {
                alert('All changes saved.');
            });
        }

        loadAll();
    </script>
</div>
</body>
</html>
'''

@app.route('/admin')
def admin():
    return render_template_string(ADMIN_TEMPLATE)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Map · Spotter</title>
    <link rel="icon" type="image/svg+xml" href="/static/logo.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/brand.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        .container { padding: 20px 30px; }
        .upload-box { background: var(--surface-1); border: 2px dashed var(--border-strong); border-radius: 10px; padding: 40px; text-align: center; margin-bottom: 30px; }
        .upload-box h3 { color: var(--accent); margin-bottom: 15px; }
        .upload-box input[type="file"] { display: none; }
        .upload-box label { display: inline-block; background: var(--accent-soft); color: var(--accent); padding: 12px 25px; border-radius: 5px; cursor: pointer; border: 1px solid var(--accent); }
        .upload-box label:hover { background: var(--accent-soft); }
        .upload-box .btn { display: inline-block; background: var(--accent-soft); color: var(--accent); padding: 12px 25px; border-radius: 5px; cursor: pointer; border: 1px solid var(--accent); margin: 10px 5px; }
        .map-container { background: var(--surface-0); border: 1px solid var(--border); border-radius: 8px; padding: 20px; min-height: 500px; position: relative; }
        .node { position: absolute; background: var(--surface-2); border: 2px solid var(--border-strong); border-radius: 50%; padding: 15px 20px; cursor: move; text-align: center; transition: box-shadow 0.3s; }
        .node:hover { box-shadow: 0 0 20px var(--accent-glow); border-color: var(--accent); }
        .node.dmz { border-color: var(--medium); }
        .node.internal { border-color: var(--text-muted); }
        .node.external { border-color: var(--high); }
        .node.compromised { border-color: var(--critical); background: var(--critical-soft); }
        .node.server { border-radius: 8px; }
        .node-label { color: var(--text); font-size: 12px; font-weight: bold; }
        .node-sublabel { color: var(--text-muted); font-size: 10px; }
        .connection { position: absolute; height: 2px; background: var(--border-strong); transform-origin: 0 50%; }
        .storyboard { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
        .story-card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
        .story-card h4 { color: var(--accent); margin-bottom: 10px; font-size: 14px; }
        .story-card p { color: var(--text-muted); font-size: 12px; line-height: 1.5; }
        .story-card img { max-width: 100%; border-radius: 5px; margin-top: 10px; }
        .back-link { color: var(--accent); text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .legend { display: flex; gap: 20px; padding: 15px; background: var(--surface-0); border-radius: 5px; margin-bottom: 20px; }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        .legend-dot { width: 15px; height: 15px; border-radius: 50%; }
        .legend-dot.dmz { background: var(--medium); }
        .legend-dot.internal { background: var(--text-muted); }
        .legend-dot.external { background: var(--high); }
        .legend-dot.compromised { background: var(--critical); box-shadow: 0 0 0 3px var(--critical-soft); }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px; cursor: pointer; }
        .tab.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
    </style>
</head>
<body>
    <nav class="sidebar" id="app-nav" data-active="network-map"></nav>
    <script src="/static/brand.js"></script>
    <div class="main-content">
    <div class="header">
        <h1>Network Map <span class="op-name" id="pageOpName"></span></h1>
    </div>
    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="showTab('map')">Network Map</div>
            <div class="tab" onclick="showTab('storyboard')">Storyboards</div>
        </div>
        <div id="map-view">
            <div class="upload-box">
                {% if success %}
                <h3 style="color:var(--accent);">Network diagram uploaded</h3>
                <p style="color:var(--accent);margin:15px 0;">Your network map has been parsed and displayed below.</p>
                {% elif error %}
                <h3 style="color:var(--critical);">Upload failed</h3>
                <p style="color:var(--critical);margin:15px 0;">Error: {{ error }}</p>
                {% else %}
                <h3>Upload a draw.io network diagram</h3>
                {% endif %}
                <form method="post" action="/api/upload-map" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".xml" style="display:block;margin:20px auto;padding:10px;background:var(--accent-soft);color:var(--text);border:1px solid var(--accent);border-radius:5px;">
                    <button type="submit" style="background:var(--accent);color:var(--bg);padding:12px 25px;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">UPLOAD XML</button>
                </form>
                <p style="color:var(--text-muted);margin-top:15px;font-size:13px;">Upload a draw.io XML file to visualize your network topology</p>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot external"></div> External</div>
                <div class="legend-item"><div class="legend-dot dmz"></div> DMZ</div>
                <div class="legend-item"><div class="legend-dot internal"></div> Internal</div>
                <div class="legend-item"><div class="legend-dot compromised"></div> Compromised</div>
            </div>
            <div class="map-container" id="mapContainer">
                {% if nodes and nodes|length > 0 %}
                    {% for node in nodes %}
                    <div class="node {{ node.type }}" style="left: {{ node.x }}px; top: {{ node.y }}px;">
                        <div class="node-label">{{ node.label }}</div>
                        {% if node.ip %}<div class="node-sublabel">{{ node.ip }}</div>{% endif %}
                    </div>
                    {% endfor %}
                {% else %}
                <p style="color:var(--text-muted);text-align:center;padding:100px;">No network map uploaded yet.<br>Upload a draw.io XML diagram above to visualize your network.</p>
                {% endif %}
            </div>
        </div>
        <div id="storyboard-view" style="display:none;">
            <div class="storyboard">
                {% for step in storyboard %}
                <div class="story-card">
                    <h4>{{ step.icon ~ ' ' if step.icon }}Phase {{ loop.index }}: {{ step.title }}</h4>
                    <p>{{ step.text }}</p>
                </div>
                {% else %}
                <div class="story-card"><p>No storyboard yet. Add phases to the "storyboard" section of data.json.</p></div>
                {% endfor %}
            </div>
        </div>
    </div>
    <script>
        function showTab(tab) {
            document.getElementById('map-view').style.display = tab === 'map' ? 'block' : 'none';
            document.getElementById('storyboard-view').style.display = tab === 'storyboard' ? 'block' : 'none';
        }
        fetch('/api/campaign').then(r => r.json()).then(c => {
            if (c.operation_name) {
                document.title = 'Network Map · ' + c.operation_name + ' · Spotter';
                document.getElementById('pageOpName').textContent = c.operation_name;
            }
        });
    </script>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return send_file(DASHBOARD_PATH)

@app.route('/network-map')
def network_map():
    nodes = load_parsed_nodes()
    success = request.args.get('success')
    error = request.args.get('error')
    storyboard = load_data()["storyboard"]
    return render_template_string(HTML_TEMPLATE, title="Network Map", nodes=nodes, success=success, error=error, storyboard=storyboard)

def load_parsed_nodes():
    map_file = os.path.join(UPLOAD_FOLDER, 'network_map.xml')
    if not os.path.exists(map_file):
        return []
    
    try:
        with open(map_file, 'r') as f:
            content = f.read()
        
        import re
        from html import unescape
        
        nodes = []
        
        # Find all vertex cells with x and y coordinates
        # Pattern looks for mxCell with vertex=1 that has x= and y= attributes directly
        cells = re.findall(r'<mxCell([^>]*vertex="1"[^>]*x="[0-9]+"[^>]*y="[0-9]+"[^>]*)>', content)
        
        for cell in cells:
            value_match = re.search(r'value="([^"]+)"', cell)
            x_match = re.search(r'x="([^"]+)"', cell)
            y_match = re.search(r'y="([^"]+)"', cell)
            style_match = re.search(r'style="([^"]+)"', cell)
            
            if not (value_match and x_match and y_match):
                continue
            
            value = value_match.group(1)
            x = x_match.group(1)
            y = y_match.group(1)
            style = style_match.group(1) if style_match else ''
            
            # Unescape HTML entities
            value = unescape(value)
            # Remove HTML tags
            clean_value = re.sub(r'<[^>]+>', '', value).strip()
            
            if not clean_value or len(clean_value) < 3:
                continue
            
            node_type = 'internal'
            style_lower = style.lower()
            
            if 'dashed' in style_lower or 'perimeter' in style_lower:
                node_type = 'dmz'
            elif 'rounded' in style_lower or 'shape=process' in style_lower:
                node_type = 'dmz'
            elif 'rhombus' in style_lower:
                node_type = 'dmz'
            elif 'ellipse' in style_lower:
                node_type = 'internal'
            
            try:
                x_pos = int(x) // 3
                y_pos = int(y) // 3
            except:
                x_pos = 100
                y_pos = 100
            
            nodes.append({
                'label': clean_value[:25],
                'ip': clean_value if '.' in clean_value and re.match(r'^[\d.]+$', clean_value) else '',
                'type': node_type,
                'x': max(50, min(x_pos, 750)),
                'y': max(50, min(y_pos, 450))
            })
        
        # If we have very few nodes, try extracting all IPs from the diagram
        if len(nodes) < 5:
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            seen = set()
            for ip in ips:
                if ip not in seen and len(nodes) < 20:
                    seen.add(ip)
                    nodes.append({
                        'label': ip,
                        'ip': ip,
                        'type': 'internal',
                        'x': 100 + len(nodes) * 90,
                        'y': 200 + (len(nodes) % 3) * 100
                    })
        
        return nodes[:30]
    except Exception as e:
        print(f"Error parsing XML: {e}")
        import traceback
        traceback.print_exc()
        return [{'label': 'Error', 'ip': '', 'type': 'internal', 'x': 300, 'y': 250}]

@app.route('/api/upload-map', methods=['POST'])
def upload_map():
    if 'file' not in request.files:
        return '''
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=no_file"></head></html>
        '''
    
    file = request.files['file']
    if file.filename == '':
        return '''
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=no_file"></head></html>
        '''
    
    if file and file.filename.endswith('.xml'):
        filename = os.path.join(UPLOAD_FOLDER, 'network_map.xml')
        file.save(filename)
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Upload successful · Spotter</title>
            <link rel="icon" type="image/svg+xml" href="/static/logo.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/brand.css">
            <style>
                .success { text-align: center; padding: 40px; background: var(--surface-1); border: 2px solid var(--accent); border-radius: 10px; }
                .success h1 { color: var(--accent); font-family: var(--font-sans); }
                .success p { color: var(--text-muted); margin: 20px 0; }
                .success .count { color: var(--accent); font-size: 48px; font-weight: bold; }
                .redirect { color: var(--text-muted); font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="success">
                <h1>Upload successful</h1>
                <p class="count">1</p>
                <p>Network diagram uploaded and parsed</p>
                <p class="redirect">Redirecting to network map...</p>
            </div>
            <meta http-equiv="refresh" content="3;url=/network-map">
        </body>
        </html>
        '''
    
    return '''
    <!DOCTYPE html>
    <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=invalid_type"></head></html>
    '''

@app.route('/api/iocs')
def iocs():
    """All indicators of compromise for the current incident, taken from data.json."""
    data = load_data()
    return jsonify({
        "ips": data["suspicious_ips"],
        "domains": data["phishing_domains"],
        "hashes": data["file_hashes"]
    })

REPORTS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IR Reports · Spotter</title>
    <link rel="icon" type="image/svg+xml" href="/static/logo.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/brand.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        .container { padding: 20px 30px; }
        .report-card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .report-header { display: flex; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px; }
        .report-header h3 { color: var(--accent); font-size: 14px; }
        .report-header .analyst { color: var(--text-muted); font-size: 12px; }
        .report-header .date { color: var(--text-muted); font-size: 12px; }
        .report-subject { color: var(--text-strong); font-size: 16px; font-weight: bold; margin-bottom: 10px; }
        .report-meta { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px; }
        .meta-item { background: var(--surface-0); padding: 8px 12px; border-radius: 4px; font-size: 12px; }
        .meta-label { color: var(--text-muted); font-size: 10px; text-transform: uppercase; }
        .meta-value { color: var(--text); margin-top: 4px; }
        .report-summary { color: var(--text-muted); font-size: 13px; line-height: 1.6; }
        .critical { border-left: 3px solid var(--critical); }
        .high { border-left: 3px solid var(--high); }
        .medium { border-left: 3px solid var(--medium); }
        .low { border-left: 3px solid var(--accent); }
        .empty { color: var(--text-muted); padding: 20px; text-align: center; }
        .search-box { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .search-box input { width: 100%; padding: 10px; background: var(--surface-0); border: 1px solid var(--border); color: var(--text); border-radius: 5px; font-size: 14px; }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 15px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px; color: var(--text-muted); cursor: pointer; font-size: 12px; }
        .filter-btn.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
    </style>
</head>
<body>
    <nav class="sidebar" id="app-nav" data-active="reports"></nav>
    <script src="/static/brand.js"></script>
    <div class="main-content">
    <div class="header">
        <h1>IR Reports <span class="op-name" id="pageOpName"></span></h1>
    </div>
    <div class="container">
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search reports by IP, subject, analyst, or keywords...">
        </div>
        <div class="filters" id="filters"></div>
        <div id="reportsContainer"></div>
    </div>
    <script>
        const SEVERITIES = ['critical', 'high', 'medium', 'low'];
        let reports = [];
        let activeFilter = 'all';

        function esc(value) {
            const div = document.createElement('div');
            div.textContent = value == null ? '' : String(value);
            return div.innerHTML;
        }

        function buildFilters() {
            const sevs = SEVERITIES.filter(s => reports.some(r => r.severity === s));
            const cats = [...new Set(reports.flatMap(r => r.categories || []))];
            const buttons = [{key: 'all', label: 'All'}]
                .concat(sevs.map(s => ({key: 'sev:' + s, label: s.charAt(0).toUpperCase() + s.slice(1)})))
                .concat(cats.map(c => ({key: 'cat:' + c, label: c})));
            const container = document.getElementById('filters');
            container.innerHTML = buttons.map(b =>
                `<div class="filter-btn${b.key === activeFilter ? ' active' : ''}" data-filter="${esc(b.key)}">${esc(b.label)}</div>`
            ).join('');
            container.querySelectorAll('.filter-btn').forEach(btn => btn.addEventListener('click', () => {
                activeFilter = btn.dataset.filter;
                buildFilters();
                applyFilters();
            }));
        }

        function searchText(r) {
            const pairs = (r.meta || []).concat(r.details || []).map(p => p.label + ' ' + p.value);
            return [r.id, r.analyst, r.date, r.subject, r.summary]
                .concat(r.tags || [], r.categories || [], pairs)
                .join(' ').toLowerCase();
        }

        function matches(r) {
            if (activeFilter.startsWith('sev:') && r.severity !== activeFilter.slice(4)) return false;
            if (activeFilter.startsWith('cat:') && !(r.categories || []).includes(activeFilter.slice(4))) return false;
            const query = document.getElementById('searchInput').value.trim().toLowerCase();
            return !query || searchText(r).includes(query);
        }

        function cardHtml(r) {
            const sev = SEVERITIES.includes(r.severity) ? r.severity : 'medium';
            const meta = (r.meta || []).map(m =>
                `<div class="meta-item"><div class="meta-label">${esc(m.label)}</div><div class="meta-value">${esc(m.value)}</div></div>`
            ).join('');
            const details = (r.details || []).map(d => `<strong>${esc(d.label)}:</strong> ${esc(d.value)}`).join('<br>');
            const summary = r.summary ? `<strong>Summary:</strong> ${esc(r.summary)}` : '';
            return `<div class="report-card ${sev}">
                <div class="report-header">
                    <h3>${esc(r.id)}</h3>
                    ${r.analyst ? `<span class="analyst">Analyst: ${esc(r.analyst)}</span>` : ''}
                    <span class="date">${esc(r.date)}</span>
                </div>
                <div class="report-subject">${esc(r.subject)}</div>
                ${meta ? `<div class="report-meta">${meta}</div>` : ''}
                <div class="report-summary">${summary}${summary && details ? '<br><br>' : ''}${details}</div>
            </div>`;
        }

        function applyFilters() {
            const container = document.getElementById('reportsContainer');
            if (!reports.length) {
                container.innerHTML = '<div class="empty">No reports yet. Add them to the "reports" section of data.json.</div>';
                return;
            }
            const shown = reports.filter(matches);
            container.innerHTML = shown.length
                ? shown.map(cardHtml).join('')
                : '<div class="empty">No reports match this search or filter.</div>';
        }

        document.getElementById('searchInput').addEventListener('input', applyFilters);
        fetch('/api/data').then(r => r.json()).then(d => {
            reports = d.reports || [];
            buildFilters();
            applyFilters();
        });
        fetch('/api/campaign').then(r => r.json()).then(c => {
            if (c.operation_name) {
                document.title = 'IR Reports · ' + c.operation_name + ' · Spotter';
                document.getElementById('pageOpName').textContent = c.operation_name;
            }
        });
    </script>
    </div>
</body>
</html>
'''

@app.route('/reports')
def reports():
    return render_template_string(REPORTS_TEMPLATE)

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

@app.route('/api/stats')
def stats():
    return jsonify(compute_stats(load_data()))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8089))
    name = load_campaign().get('operation_name') or 'Threat Hunt Dashboard'
    print("=" * 50)
    print("SPOTTER  |  " + name)
    print(f"Running on http://0.0.0.0:{port}")
    print("=" * 50)
    try:
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"Server error: {e}")
