# Spotter

**The common operating picture for cyber exercises and incident response teams.**

Spotter gives an IR team one shared picture of an operation: the attack timeline mapped to MITRE ATT&CK, indicators of compromise, affected users and systems, incident reports, and the team's next actions. It is built for cyber exercises, training and competitions, where a team needs that picture running in seconds and visible to leadership.

Spotter is not a threat hunting tool: it doesn't query logs or telemetry. Analysts record what they find in their other tools, and Spotter keeps everyone, including leadership, on the same page.

The repository contains no mission data. Each user's operation lives in local files that are created on first run and never committed, so the same install can be reused for any operation.

## Features

### Dashboard
- Attack chain timeline with MITRE ATT&CK technique mapping
- Suspicious IP & phishing domain IOC panels
- Threat intelligence feed with predicted next moves
- Actionable recommendations with MITRE mitigation IDs
- Real-time incident stats (IOCs, compromised users, affected systems)

### Network Map
- Upload draw.io XML diagrams to visualize network topology
- Color-coded nodes (External, DMZ, Internal, Compromised)
- Storyboard view showing attack phases from initial access to defense evasion

### IR Reports
- Searchable incident report cards with analyst attribution
- Filter by severity (Critical/High/Medium), category (Malware, Lateral Movement, Recon)
- Detailed metadata: operation ID, discovery DTG, hostile IPs, affected hosts

### Admin Console
- Full CRUD for all dashboard data (IPs, domains, timeline events, recommendations)
- Inline editing with date/time pickers
- One-click save to persist changes to `data.json`

## Tech Stack

- **Backend:** Flask, served by Waitress
- **Frontend:** Vanilla HTML/CSS/JS
- **Fonts:** Inter and JetBrains Mono (Google Fonts)
- **Brand:** colours, fonts and the logo live in `static/brand.css`, `static/brand.js` and `static/logo.svg`. Change the variables at the top of `brand.css` to re-theme every page.
- **Data:** JSON-based persistence via `data.json`

## Quick Start

### Prerequisites
- Python 3.9 or newer

### Linux and macOS

```bash
bash start_server.sh
```

The first run creates a Python virtual environment in `.venv` and installs the requirements, which takes about a minute. Spotter then runs in the background and writes its output to `server.log`. Stop it with `pkill -f server.py`.

### Windows

```powershell
py -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python server.py
```

### Open it

Go to **http://localhost:8089**. These settings can be changed with environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8089` | Port to listen on |
| `HOST` | `0.0.0.0` | Address to listen on. `0.0.0.0` makes Spotter reachable from other computers on your network; use `127.0.0.1` to keep it on this computer only |
| `SPOTTER_DATA_DIR` | the project folder | Where `data.json`, `campaign.json` and `uploads/` are kept |

```bash
PORT=9000 HOST=127.0.0.1 python3 server.py
```

> **Spotter has no login yet.** Anyone who can reach it can view and edit the operation. Until logins arrive (see the roadmap), only run it on networks you trust, or set `HOST=127.0.0.1`.

## Pages & Routes

| Route | Description |
|-------|-------------|
| `/` | Main threat dashboard with timeline, IOCs, and stats |
| `/network-map` | Network topology visualizer with draw.io upload |
| `/reports` | Searchable incident response report cards |
| `/admin` | Admin console for editing all dashboard data |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/data` | GET | Retrieve all dashboard data (timeline, IPs, domains, recommendations, threat intel) |
| `/api/data` | POST | Update dashboard data (accepts full JSON payload) |
| `/api/iocs` | GET | IOC list (IPs, domains, file hashes) taken from `data.json` |
| `/api/stats` | GET | Headline counts (IOCs, compromised users, affected systems, MITRE techniques, reports) calculated from `data.json` |
| `/api/campaign` | GET/POST | Read or update the campaign settings in `campaign.json` |
| `/api/upload-map` | POST | Upload a draw.io XML network diagram |

## File Structure

```
spotter/
├── server.py              # Starts Spotter (Waitress, or Flask's server as a fallback)
├── start_server.sh        # One-command start for Linux and macOS
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # Adds pytest for development
├── spotter/               # The application
│   ├── __init__.py        # create_app(): builds the Flask app
│   ├── pages.py           # HTML page routes
│   ├── api.py             # /api/* routes
│   ├── storage.py         # Reading and writing data.json / campaign.json, defaults, stats
│   └── netmap.py          # draw.io diagram parser for the network map
├── templates/             # One HTML template per page, plus the shared <head>
├── static/
│   ├── brand.css          # Spotter colours, fonts and shared components
│   ├── brand.js           # Navigation rail with logo
│   ├── logo.svg           # Logo and browser tab icon
│   ├── css/               # Styles for each page
│   └── js/                # Scripts for each page
├── tests/                 # pytest tests
├── data.json              # Your incident data (created on first run, not in git)
├── campaign.json          # Your operation settings (created on first run, not in git)
└── uploads/               # Your uploaded draw.io diagram (not in git)
```

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The tests use a temporary data folder, so they never touch your own `data.json` or `campaign.json`.

## Data

The dashboard code contains no incident content. Everything specific to an operation lives in two files:

- **`campaign.json`** — the operation's identity and labels: operation name, subtitle, team, dashboard title, status, alert banner, kill chain phases and panel titles.
- **`data.json`** — the incident data:

| Section | What it holds | Shown on |
|---------|---------------|----------|
| `timeline` | Attack chain events with MITRE ATT&CK mappings | Dashboard |
| `suspicious_ips` | Tracked hostile/recon IPs with status | Dashboard, `/api/iocs` |
| `phishing_domains` | Identified phishing & C2 domains | Dashboard, `/api/iocs` |
| `file_hashes` | Malicious file hashes | `/api/iocs` |
| `threat_intel` | Predicted adversary next moves | Dashboard |
| `recommendations` | Remediation actions | Dashboard |
| `compromised_users` | Usernames confirmed compromised | Dashboard stat |
| `affected_systems` | Hostnames affected by the incident | Dashboard stat |
| `reports` | Incident report cards | IR Reports page |
| `storyboard` | Attack phases, in order | Network Map → Storyboard |

### Starting a new operation

The first time the server runs, it creates an empty `data.json` and a `campaign.json` with neutral default labels and a standard MITRE ATT&CK kill chain. Fill them in through the Admin page or by editing the files directly.

These files, and anything in `uploads/`, are listed in `.gitignore`, so your mission data stays on your computer and is never pushed to GitHub. Back them up yourself if you need to keep them. To start over, stop the server, move or delete the two files, and start it again.

Any section can be left out or empty. Missing sections are treated as empty lists, and missing settings fall back to the defaults.

### Report format

Each entry in `reports` looks like this. Only `id` and `subject` are needed; the rest is optional. The filter buttons on the Reports page are built from the severities and `categories` in use.

```json
{
  "id": "IR-0001",
  "analyst": "Analyst name",
  "date": "Jan 15, 2026 2:30 PM",
  "severity": "critical",
  "subject": "Malicious attachment opened on workstation",
  "categories": ["Malware"],
  "tags": ["phishing", "reverse", "shell"],
  "meta": [
    {"label": "Hostile IPs", "value": "203.0.113.10"},
    {"label": "Affected Hosts", "value": "WS-01, WS-02"}
  ],
  "summary": "What happened, how it was found, and what it affected.",
  "details": [
    {"label": "Tools", "value": "invoice.pdf.exe"}
  ]
}
```

`severity` is one of `critical`, `high`, `medium` or `low`. `tags` are extra search keywords.

### Storyboard format

```json
{"icon": "🎯", "title": "Initial Access", "text": "How the attacker first got in."}
```

Phases are numbered automatically in the order listed.

## Roadmap

Spotter is heading toward a v1.0 built for cyber exercises and incident response teams: multi-user editing, logins, live updates, a briefing mode for wall screens, and after-action report export. See [ROADMAP.md](ROADMAP.md) for the full plan.
