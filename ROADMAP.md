# Spotter Roadmap

**Spotter: the common operating picture for cyber exercises and incident response teams.**

Spotter is not a threat hunting tool: it does not query telemetry. It is the shared picture an IR team builds as it works: what happened, what is compromised, and what the team is doing next. It is built first for cyber exercises, training and competitions, where a team needs that picture running in seconds and visible to leadership.

## Definition of v1.0

A five-person team runs a week-long exercise on Spotter:

- each analyst logs in and records findings at the same time, with no lost work
- leadership watches a briefing screen that updates live
- on the last day, the team exports an after-action report as a PDF in one click

Sizes: **S** = an afternoon or two, **M** = a few days, **L** = a week or more.

---

## Phase 0: Foundation

*Make the code safe to grow. No new features for users.*

- [ ] **0.1** Commit and push the Spotter brand work (S)
- [ ] **0.2** Decide on git history: keep it, or start a fresh repo with a clean first commit (old mission data is still in past commits) (S)
- [ ] **0.3** Split `server.py` into modules, move HTML into `templates/` and JavaScript into `static/` (M)
- [ ] **0.4** Add pytest tests that load every page and endpoint (S)
- [ ] **0.5** Run on Waitress instead of Flask's development server (S)

## Phase 1: Data you can trust

*Fix the problems that would embarrass Spotter in a real exercise.*

- [ ] **1.1** Move storage from JSON files to SQLite (`spotter.db`, kept out of git) (M)
- [ ] **1.2** Multiple operations per install, with archive and delete (M)
- [ ] **1.3** Full UTC timestamps everywhere, displayed as military DTG (`231300Z APR 26`) with a local-time toggle (M)
- [ ] **1.4** Save each item individually instead of overwriting the whole file (M)
- [ ] **1.5** One-time import of existing `data.json` / `campaign.json` (S)

## Phase 2: Safe for a team

*Make Spotter safe to put on a shared network.*

- [ ] **2.1** Login with three roles: Viewer (read-only), Analyst (add and edit), Admin (users, operations, settings); first run creates the admin account (M)
- [ ] **2.2** Only reachable from the local computer by default; network access is an explicit setting (S)
- [ ] **2.3** CSRF protection and login rate limiting (S)
- [ ] **2.4** Audit log: who changed what, when, and the previous value (M)
- [ ] **2.5** Edit-conflict warning when someone else changed an item first (S)

## Phase 3: The live operating picture

*The phase that makes Spotter worth choosing.*

- [ ] **3.1** Live updates: every open screen updates within a second of any save (Server-Sent Events) (M)
- [ ] **3.2** Activity feed built on the audit log (S)
- [ ] **3.3** Briefing mode: full-screen, read-only, large text, rotating panels for wall screens and leadership briefings (M)
- [ ] **3.4** Operation switcher in the top bar and a "New operation" setup wizard (S)
- [ ] **3.5** "Last updated" time and status indicator on every page (S)

> **Test with real users after Phase 3.** Run Spotter in an actual exercise, class or practice session, and let their feedback set the priorities for Phases 4 to 6.

## Phase 4: Editing that's fast under pressure

- [ ] **4.1** Rebuild the admin page around tables with inline editing and a side editing panel (L)
- [ ] **4.2** Editors for reports, storyboard, file hashes, users, systems and campaign settings (M)
- [ ] **4.3** Quick-add from any page: press `N`, paste an IOC, its type (IP, domain, hash) is detected automatically (M)
- [ ] **4.4** Notifications with Undo instead of browser `alert()` popups (S)
- [ ] **4.5** Link items together: reports reference IOCs and hosts; clicking one filters everything (M)

## Phase 5: Outputs

*What the team walks away with.*

- [ ] **5.1** After-action report export: print-ready page saved as PDF (M)
- [ ] **5.2** IOC export as CSV and STIX 2.1 (S)
- [ ] **5.3** Operation templates: clone an operation's setup without its findings (S)
- [ ] **5.4** Backup and restore of an operation as a single file (S)
- [ ] **5.5** ATT&CK coverage view: every tactic, shaded by techniques observed (M)

## Phase 6: Ship v1.0

- [ ] **6.1** Rebuild the network map with connection lines, zones, zoom and pan (Cytoscape.js) (L)
- [ ] **6.2** Theme presets built on `static/brand.css` (S)
- [ ] **6.3** One-click fictional demo operation (S)
- [ ] **6.4** Docker image and one-command start for Windows, Mac and Linux (S)
- [ ] **6.5** README with screenshots and demo; GitHub Actions running the tests (S)
- [ ] **6.6** Tag the v1.0 release (S)

## Later, if exercise users ask for it

- Exercise control: scheduled scenario events ("injects") and scoring for exercise staff
- Multiple teams in one operation, each seeing only its own data
- Connectors that import findings from DFIR-IRIS, TheHive or Security Onion
