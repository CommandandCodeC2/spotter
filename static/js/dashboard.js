// Spotter dashboard: design handoff v2, option 2a.
// Three views from the same data: the dashboard, a first-run setup for an
// empty operation, and a wall display (?view=wall).
(function () {
    'use strict';

    // ---------- Reference data ----------

    // MITRE ATT&CK Enterprise tactics
    const TACTICS = {
        TA0043: 'Reconnaissance', TA0042: 'Resource Development', TA0001: 'Initial Access',
        TA0002: 'Execution', TA0003: 'Persistence', TA0004: 'Privilege Escalation',
        TA0005: 'Defense Evasion', TA0006: 'Credential Access', TA0007: 'Discovery',
        TA0008: 'Lateral Movement', TA0009: 'Collection', TA0011: 'Command and Control',
        TA0010: 'Exfiltration', TA0040: 'Impact'
    };
    const DEFAULT_CHAIN = ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006',
                           'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'];
    const TACTIC_BY_NAME = {};
    Object.entries(TACTICS).forEach(([id, name]) => { TACTIC_BY_NAME[norm(name)] = id; });
    Object.assign(TACTIC_BY_NAME, {
        privesc: 'TA0004', recon: 'TA0043', c2: 'TA0011', commandcontrol: 'TA0011',
        lateral: 'TA0008', exfil: 'TA0010', credaccess: 'TA0006', defenseevasion: 'TA0005'
    });

    const SEV = {
        critical: { color: 'var(--critical)', label: 'CRITICAL' },
        high:     { color: 'var(--high)',     label: 'HIGH' },
        medium:   { color: 'var(--medium)',   label: 'MEDIUM' },
        low:      { color: 'var(--low)',      label: 'LOW' }
    };
    const HOT_STATUSES = ['ACTIVE', 'COMPROMISED'];
    const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

    // Machine data shown in monospace inside free text. Analysts can also
    // wrap anything in `backticks` to force it.
    const MONO_RE = new RegExp([
        '`[^`]+`',
        'https?:\\/\\/[^\\s<>"\']+',
        '[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+',
        '\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?:\\/\\d{1,2}|:\\d{1,5})?\\b',
        '\\b[a-fA-F0-9]{32,}\\b',
        '\\b[A-Za-z]:\\\\[^\\s,;)"\']*',
        '%[A-Za-z_]+%',
        '\\b[\\w-]+(?:\\.[\\w-]+)*\\.(?:exe|EXE|dll|DLL|ps1|bat|cmd|vbs|js|jar|docm|docx|doc|xlsm|xlsx|pdf|zip|rar|7z|iso|lnk|hta|msi|sys|scr|py|sh|elf|bin|dmp|tmp)\\b',
        '\\*?\\.?\\b(?:[a-z0-9-]+\\.)+(?:com|net|org|io|gov|mil|edu|info|biz|ru|cn|pl|uk|de|fr|example|invalid|test|local|lan|corp|internal|xyz|top|online|site|club|co|us|me|app|dev)\\b',
        '\\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[A-Z0-9]*\\d[A-Z0-9]*\\b',
        '\\bsvc_\\w+',
        '\\b[a-z]+\\.[a-z]{2,}\\b',
        '\\bkrbtgt\\b'
    ].join('|'), 'g');

    // ---------- State ----------

    const params = new URLSearchParams(location.search);
    const state = {
        data: null, campaign: null, stats: null,
        tactic: null, tab: 'All',
        wall: params.get('view') === 'wall',
        pending: new Set(),
        highlight: null
    };
    const main = document.getElementById('dashMain');
    const toastEl = document.getElementById('toast');
    let toastTimer = null;

    // ---------- Small helpers ----------

    function norm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function monoHtml(text) {
        text = String(text == null ? '' : text);
        let out = '', last = 0;
        for (const m of text.matchAll(MONO_RE)) {
            let token = m[0];
            if (token.startsWith('`')) token = token.slice(1, -1);
            out += esc(text.slice(last, m.index));
            out += `<span class="inline-mono${token.length < 28 ? ' short' : ''}">${esc(token)}</span>`;
            last = m.index + m[0].length;
        }
        return out + esc(text.slice(last));
    }

    const pad = n => String(n).padStart(2, '0');

    function opYear() {
        const y = parseInt(state.campaign && state.campaign.year, 10);
        return y > 1999 ? y : new Date().getUTCFullYear();
    }

    // Times are stored like "MAR 12 03:50" (treated as Zulu), "MAR 12", "TBD",
    // or ISO 8601. Returns { date, hasTime } or null when undated.
    function parseWhen(value) {
        if (!value) return null;
        const s = String(value).trim();
        const m = s.match(/^([A-Za-z]{3})[A-Za-z]*\s+(\d{1,2})(?:\s+(\d{1,2}):?(\d{2})Z?)?$/);
        if (m) {
            const mon = MONTHS.indexOf(m[1].toUpperCase());
            if (mon < 0) return null;
            const hasTime = m[3] !== undefined;
            return { date: new Date(Date.UTC(opYear(), mon, +m[2], hasTime ? +m[3] : 0, hasTime ? +m[4] : 0)), hasTime };
        }
        if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
            const d = new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(s) || s.length === 10 ? s : s + 'Z');
            if (!isNaN(d)) return { date: d, hasTime: s.length > 10 };
        }
        return null;
    }

    const zulu = d => pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + 'Z';
    const dtgShort = d => pad(d.getUTCDate()) + zulu(d);
    const dtg = d => dtgShort(d) + ' ' + MONTHS[d.getUTCMonth()] + ' ' + String(d.getUTCFullYear()).slice(2);
    const dayKey = d => d.getUTCFullYear() + '-' + d.getUTCMonth() + '-' + d.getUTCDate();
    const dayLabel = d => MONTHS[d.getUTCMonth()] + ' ' + pad(d.getUTCDate());

    function ago(ms) {
        const mins = Math.max(0, Math.floor(ms / 60000));
        if (mins < 1) return 'just now';
        if (mins < 60) return mins + 'm ago';
        const h = Math.floor(mins / 60);
        if (h < 48) return h + 'h ' + (mins % 60) + 'm ago';
        return Math.floor(h / 24) + 'd ' + (h % 24) + 'h ago';
    }

    function tplus(ms) {
        if (ms < 0) return 'T−' + tplus(-ms).slice(2);
        const mins = Math.floor(ms / 60000), hours = Math.floor(mins / 60);
        if (hours >= 100) return 'T+' + Math.floor(hours / 24) + 'd' + pad(hours % 24) + 'h';
        return 'T+' + hours + 'h' + pad(mins % 60);
    }

    function initials(name) {
        const s = String(name || '').trim();
        if (!s) return '';
        if (/^[A-Z]{1,3}$/.test(s)) return s;
        const words = s.replace(/[^A-Za-z\s.-]/g, '').split(/[\s.-]+/).filter(Boolean);
        return (words.length > 1 ? words[0][0] + words[words.length - 1][0] : s.slice(0, 2)).toUpperCase();
    }

    function statusWord(s) {
        s = String(s || '').trim();
        return s === s.toUpperCase() ? s.charAt(0) + s.slice(1).toLowerCase() : s;
    }

    function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

    function tacticOf(e) {
        const m = String(e.tactics || '').match(/TA\d{4}/);
        return m ? m[0] : null;
    }

    function phaseState(status) {
        const s = norm(status);
        if (s === 'active' || s === 'seen') return 'seen';
        if (s === 'hunt' || s === 'investigating') return 'hunt';
        return 'notseen';
    }

    const ICON_COPY = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
    const ICON_X = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>';
    const ICON_CHECK = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>';

    // ---------- Derived model ----------

    function buildModel() {
        const d = state.data, c = state.campaign;

        const events = (d.timeline || []).map((e, idx) => {
            const when = parseWhen(e.time);
            return { e, idx, when, ta: tacticOf(e) };
        });
        const dated = events.filter(x => x.when);
        const undated = events.filter(x => !x.when).sort((a, b) => b.idx - a.idx); // newest first
        dated.sort((a, b) => b.when.date - a.when.date || b.idx - a.idx);

        // Patient zero: set explicitly, or the first timed event
        let pz = parseWhen(c.patient_zero_time), pzExplicit = !!pz;
        if (!pz) {
            const timed = dated.filter(x => x.when.hasTime);
            pz = timed.length ? timed[timed.length - 1].when : (dated.length ? dated[dated.length - 1].when : null);
        }
        const pzDay = pz ? Date.UTC(pz.date.getUTCFullYear(), pz.date.getUTCMonth(), pz.date.getUTCDate()) : null;
        const dayNumber = date => pzDay === null ? null :
            Math.floor((Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) - pzDay) / 86400000) + 1;

        // Latest briefing
        const briefings = (d.briefings || [])
            .map(b => parseWhen(typeof b === 'object' && b ? b.time : b))
            .filter(Boolean).sort((a, b) => b.date - a.date);
        const briefing = briefings[0] || null;
        const sinceBriefing = briefing ? dated.filter(x => x.when.date > briefing.date).length : 0;

        // Attack chain columns
        const phases = Array.isArray(c.kill_chain_phases) && c.kill_chain_phases.length
            ? c.kill_chain_phases
            : DEFAULT_CHAIN.map(id => ({ name: TACTICS[id], status: '' }));
        const counts = {};
        events.forEach(x => { if (x.ta) counts[x.ta] = (counts[x.ta] || 0) + 1; });
        const chain = phases.map(p => {
            const id = (p.id && TACTICS[p.id] ? p.id : TACTIC_BY_NAME[norm(p.name)]) || null;
            const count = id ? (counts[id] || 0) : 0;
            // A tactic with recorded events is "seen" even if nobody updated its status by hand
            let st = phaseState(p.status);
            if (st === 'notseen' && count > 0) st = 'seen';
            return { id, name: p.name || TACTICS[id] || '', state: st, count };
        });

        const latestDay = dated.length ? dayNumber(dated[0].when.date) : null;
        const empty = ['timeline', 'suspicious_ips', 'phishing_domains', 'file_hashes', 'reports',
                       'recommendations', 'threat_intel', 'compromised_users', 'affected_systems']
            .every(k => !(d[k] || []).length);

        return { events, dated, undated, pz, pzExplicit, dayNumber, briefing, sinceBriefing, chain, latestDay, empty };
    }

    // ---------- Top bar ----------

    function renderTopbar(model) {
        const c = state.campaign;
        const setup = model.empty;
        const name = c.operation_name && c.operation_name !== 'New Operation' ? c.operation_name : 'Untitled operation';
        document.getElementById('opName').textContent = name;
        document.title = name + ' · Spotter';

        let context = [];
        if (setup) {
            context = ['<strong>Setup</strong>'];
        } else {
            if (c.subtitle) context.push(esc(c.subtitle));
            if (model.latestDay) {
                const of = parseInt(c.duration_days, 10);
                context.push('Day ' + model.latestDay + (of > 0 ? ' of ' + of : ''));
            }
            if (c.status) context.push('<strong>' + esc(statusWord(c.status)) + '</strong>');
        }
        document.getElementById('opContext').innerHTML = context.join(' · ');
        document.getElementById('wallLink').hidden = setup;
        updateClock();
    }

    function updateClock() {
        const parts = [dtg(new Date())];
        if (state.stats && state.stats.updated_at) {
            parts.push('updated ' + ago(Date.now() - new Date(state.stats.updated_at)));
        }
        const text = parts.join(' · ');
        document.getElementById('clock').textContent = text;
        const wallClock = document.getElementById('wallClock');
        if (wallClock) wallClock.textContent = text;
    }

    // ---------- 1. Headline ----------

    function headlineHtml(model) {
        const c = state.campaign, s = state.stats;
        const alert = c.alert_banner || {};
        const hasAlert = !!(alert.message || alert.title);
        let meta, text, link = '';

        if (hasAlert) {
            const sevKey = String(alert.severity || 'critical').toLowerCase();
            const sev = SEV[sevKey] || SEV.critical;
            const bits = [];
            if (alert.report_id) bits.push(esc(alert.report_id));
            const raised = parseWhen(alert.raised_at);
            if (raised) bits.push('raised ' + dtgShort(raised.date), ago(Date.now() - raised.date));
            if (alert.raised_by) bits.push(esc(alert.raised_by));
            if (!alert.report_id && alert.title && alert.message) bits.push(esc(alert.title));
            meta = `<span class="pulse-dot${sevKey === 'critical' ? ' live' : ''}" style="background:${sev.color}"></span>
                    <span class="sev-word" style="color:${sev.color}">${sev.label}</span>
                    ${bits.length ? `<span class="mono">${bits.join(' · ')}</span>` : ''}`;
            text = monoHtml(alert.message || alert.title);
            if (alert.report_id) link = `<a class="headline-link" href="/reports?q=${encodeURIComponent(alert.report_id)}">Open report →</a>`;
        } else {
            meta = `<span class="pulse-dot" style="background:var(--text-muted)"></span>
                    <span class="sev-word" style="color:var(--text-muted)">${esc(String(c.status || 'Status not set').toUpperCase())}</span>`;
            text = monoHtml(c.description || c.operation_name || '');
        }

        const counts = [
            ['compromised_users', 'compromised user', 'compromised users', null, (state.data.compromised_users || []).join(', ')],
            ['affected_systems', 'affected system', 'affected systems', null, (state.data.affected_systems || []).join(', ')],
            ['active_iocs', 'active indicator', 'active indicators', '#indicators', ''],
            ['mitre_techniques', 'ATT&CK technique', 'ATT&CK techniques', '#attack-chain', '']
        ].map(([key, one, many, href, tip]) => {
            const n = s[key] || 0;
            const inner = `<span class="count-num">${n}</span><span class="count-label">${esc(n === 1 ? one : many)}</span>`;
            return href
                ? `<a class="count" href="${href}">${inner}</a>`
                : `<span class="count"${tip ? ` title="${esc(tip)}"` : ''}>${inner}</span>`;
        }).join('');

        const since = model.briefing && !state.wall
            ? `<span class="since">Since the <span class="mono">${dtgShort(model.briefing.date)}</span> briefing: <span class="change">${plural(model.sinceBriefing, 'new event', 'new events')}</span></span>`
            : '';

        return `<section class="headline" aria-label="Situation">
            <div class="headline-main">
                <div class="headline-meta">${meta}</div>
                <h1>${text}</h1>
            </div>
            ${link || '<span></span>'}
            <div class="counts">${counts}${since}</div>
        </section>`;
    }

    // ---------- 2. Attack chain ----------

    function chainHtml(model, opts) {
        const interactive = !opts.disabled && !state.wall;
        const cols = model.chain.map(t => {
            const st = opts.allNotSeen ? 'notseen' : t.state;
            const pressed = interactive && state.tactic && state.tactic === t.id;
            const label = st === 'seen' ? 'SEEN' : st === 'hunt' ? 'HUNT' : '';
            return `<button class="tactic ${st}" type="button" data-tactic="${esc(t.id || '')}"
                        aria-pressed="${pressed ? 'true' : 'false'}" ${interactive && t.id ? '' : 'disabled'}
                        title="${esc(t.name)}${t.id ? ' (' + t.id + ')' : ''}">
                    <div class="bar bar-${st}"></div>
                    <span class="tactic-count">${opts.allNotSeen ? 0 : t.count}</span>
                    <div class="tactic-name">${esc(t.name)}</div>
                    <div class="tactic-id">${esc(t.id || '')}${label ? ` <b>${label}</b>` : ''}</div>
                </button>`;
        }).join('');

        const legend = opts.allNotSeen ? '' : `<div class="legend">
                <span><span class="swatch bar-seen"></span>Seen</span>
                <span><span class="swatch bar-hunt"></span>Investigating</span>
                <span><span class="swatch bar-notseen"></span>Not seen</span>
            </div>`;

        return `<section class="chain" id="attack-chain" aria-label="Attack chain">
            <div class="section-head">
                <h2>Attack chain</h2>
                <span class="hint">${opts.hint}</span>
                <span class="spacer"></span>
                ${legend}
            </div>
            <div class="strip" style="grid-template-columns:repeat(${model.chain.length},minmax(0,1fr))">${cols}</div>
        </section>`;
    }

    // ---------- 3a. Timeline ----------

    function sevOf(e) {
        const key = String(e.severity || '').toLowerCase();
        return SEV[key] || { color: 'var(--medium)', label: key ? key.toUpperCase() : 'MEDIUM' };
    }

    function eventHtml(x, model) {
        const e = x.e, sev = sevOf(e);
        const unconfirmed = e.confirmed === false;
        const time = x.when && x.when.hasTime ? zulu(x.when.date) : '—';
        let tp = '';
        if (x.when && x.when.hasTime && model.pz) tp = tplus(x.when.date - model.pz.date);
        else if (!x.when && model.pz) tp = 'T+?';
        const tacticName = x.ta ? TACTICS[x.ta] || x.ta : '';
        const who = initials(e.logged_by);
        const fresh = state.highlight === x.idx ? ' just-added' : '';
        return `<div class="event${unconfirmed ? ' unconfirmed' : ''}${fresh}">
            <div class="event-when"><span class="event-time">${time}</span><span class="event-tplus">${tp}</span></div>
            <div class="event-rail"><div class="event-dot" style="color:${sev.color}"></div></div>
            <div class="event-body">
                <div class="event-title-row">
                    <span class="event-title">${esc(e.title || 'Untitled event')}</span>
                    ${unconfirmed ? '<span class="tag-unconfirmed">Unconfirmed</span>' : ''}
                </div>
                <div class="event-meta">
                    <span class="sev-label" style="color:${sev.color}">${esc(sev.label)}</span>
                    ${e.tech ? `<span>·</span><span class="mono">${esc(e.tech)}</span>` : ''}
                    ${tacticName ? `<span>${esc(tacticName)}</span>` : ''}
                </div>
                ${e.desc || e.impact ? `<div class="event-desc">${monoHtml(e.desc)}${e.impact ? `<span class="impact">${e.desc ? ' — ' : ''}${esc(e.impact)}</span>` : ''}</div>` : ''}
            </div>
            <div class="event-who">${who ? `<span class="initials" title="Logged by ${esc(e.logged_by)}">${esc(who)}</span>` : ''}</div>
        </div>`;
    }

    function briefingHtml(model) {
        return `<div class="briefing">
            <span class="briefing-label">LAST BRIEFING</span>
            <span class="mono">${dtg(model.briefing.date)}</span>
            <span class="briefing-line"></span>
            <span class="briefing-since">${plural(model.sinceBriefing, 'event', 'events')} since</span>
        </div>`;
    }

    function timelineHtml(model) {
        const sel = state.tactic;
        const keep = x => !sel || x.ta === sel;
        const undated = model.undated.filter(keep);
        const dated = model.dated.filter(keep);
        const total = model.events.length;
        const shown = undated.length + dated.length;

        let html = '';
        if (undated.length) {
            html += `<div class="day"><div class="day-head"><span class="mono">UNDATED</span><span class="muted">Under investigation</span></div>
                ${undated.map(x => eventHtml(x, model)).join('')}</div>`;
        }

        // Group by day, newest first, with the briefing marker where it falls
        const showMarker = model.briefing && !sel;
        let markerDone = !showMarker;
        let i = 0;
        while (i < dated.length) {
            const key = dayKey(dated[i].when.date);
            const group = [];
            while (i < dated.length && dayKey(dated[i].when.date) === key) group.push(dated[i++]);
            const first = group[0].when.date;
            const n = model.dayNumber(first);
            let body = '';
            group.forEach((x, j) => {
                if (!markerDone && x.when.date <= model.briefing.date) {
                    if (j === 0) html += briefingHtml(model); else body += briefingHtml(model);
                    markerDone = true;
                }
                body += eventHtml(x, model);
            });
            html += `<div class="day"><div class="day-head"><span class="mono">${dayLabel(first)}</span>${n ? `<span class="muted">Day ${n}</span>` : ''}</div>${body}</div>`;
        }
        if (!markerDone) html += briefingHtml(model);

        if (!shown) {
            html = `<div class="timeline-empty">${sel ? 'No events recorded for this tactic yet.' : 'No timeline events recorded yet. <button class="timeline-add" type="button" data-open-drawer>Add the first one</button>.'}</div>`;
        }

        const countText = sel ? `${shown} of ${total} events` : `${plural(total, 'event', 'events')} · newest first`;
        const chip = sel ? `<button class="filter-chip" type="button" data-clear-filter aria-label="Clear filter ${esc(TACTICS[sel] || sel)}">${esc(TACTICS[sel] || sel)}${ICON_X}</button>` : '';
        const legend = model.pz
            ? `<span class="hint">T+ = time since ${model.pzExplicit ? 'patient zero' : 'first event'}, <span class="mono">${dtgShort(model.pz.date)}</span></span>`
            : '';

        return `<section aria-label="Timeline" style="min-width:0">
            <div class="timeline-head">
                <h2>Timeline</h2>
                <span class="hint">${countText}</span>
                ${chip}
                <span style="flex:1"></span>
                ${legend}
                ${state.wall ? '' : '<button class="timeline-add" type="button" data-open-drawer>Add</button>'}
            </div>
            ${html}
        </section>`;
    }

    // ---------- 3b. Right column ----------

    function actionsHtml() {
        const recs = (state.data.recommendations || []).map((r, idx) => ({ r, idx, done: r.status === 'completed' }));
        const open = recs.filter(x => !x.done).length;
        recs.sort((a, b) => (a.done - b.done) || (a.idx - b.idx));
        const rows = recs.map(({ r, idx, done }) => `<div class="action${done ? ' done' : ''}">
                <button class="checkbox" type="button" data-rec="${idx}" aria-pressed="${done}"
                        aria-label="${done ? 'Mark as not done' : 'Mark as done'}" ${state.pending.has(idx) ? 'disabled' : ''}>${ICON_CHECK}</button>
                <div class="action-text"><span>${monoHtml(r.text)}</span>${r.mitre ? `<span class="action-mitre">${esc(r.mitre)}</span>` : ''}</div>
            </div>`).join('');
        return `<section class="actions" aria-label="Next actions">
            <div class="section-head actions-head">
                <h2>Next actions</h2>
                <span class="count-text">${open} open · ${recs.length - open} done</span>
                <span class="spacer"></span>
                <a href="/admin">Add</a>
            </div>
            <div class="actions-list">${rows || '<div class="panel-empty">No actions recorded yet.</div>'}</div>
        </section>`;
    }

    function movesHtml() {
        const items = (state.data.threat_intel || []).map(t => {
            const m = String(t.text || '').match(/^\s*(LIKELY|POSSIBLE|UNLIKELY|CONFIRMED|EXPECTED)\s*:?\s*(.*)$/i);
            let like = m ? m[1].toUpperCase() : '', rest = m ? m[2] : String(t.text || '');
            const tech = t.mitre || (rest.match(/T\d{4}(?:\.\d{3})?/) || [''])[0];
            rest = rest.replace(new RegExp('^' + tech.replace('.', '\\.') + '\\s*[-–—:]\\s*'), '');
            return `<div class="move">
                <span class="move-like${like === 'LIKELY' || like === 'CONFIRMED' ? ' likely' : ''}">${esc(like)}</span>
                <span class="move-text">${monoHtml(rest)}${tech ? ` <span class="mono">${esc(tech)}</span>` : ''}</span>
            </div>`;
        }).join('');
        return `<section aria-label="Expected next moves">
            <div class="section-head list-head"><h2>Expected next moves</h2><span class="hint">From threat intel</span></div>
            ${items || '<div class="ioc-empty">No threat intel recorded yet.</div>'}
        </section>`;
    }

    function indicatorList() {
        const d = state.data;
        const uniq = arr => arr.filter((v, i) => v && arr.indexOf(v) === i);
        const list = [];
        (d.suspicious_ips || []).forEach(x => list.push({
            kind: 'IP', value: x.ip, copy: x.ip, sub: uniq([x.type, x.label]).join(' · '), status: x.status }));
        (d.phishing_domains || []).forEach(x => list.push({
            kind: 'Domain', value: x.domain, copy: x.domain, sub: x.type || '', status: x.status }));
        (d.file_hashes || []).forEach(x => {
            const h = String(x.hash || '');
            list.push({ kind: 'Hash', value: h.length > 24 ? h.slice(0, 12) + '…' + h.slice(-8) : h, copy: h,
                        sub: uniq([x.name, x.type]).join(' · '), status: x.status });
        });
        const order = { IP: 0, Domain: 1, Hash: 2 };
        const hot = o => HOT_STATUSES.includes(String(o.status || '').toUpperCase()) ? 0 : 1;
        return list.map((o, i) => ({ ...o, i }))
            .sort((a, b) => order[a.kind] - order[b.kind] || hot(a) - hot(b) || a.i - b.i);
    }

    function indicatorsHtml() {
        const all = indicatorList();
        const tabs = [['All', 'All'], ['IP', 'IPs'], ['Domain', 'Domains'], ['Hash', 'Hashes']];
        const tabHtml = tabs.map(([key, label]) => {
            const n = key === 'All' ? all.length : all.filter(o => o.kind === key).length;
            return `<button class="ioc-tab" type="button" role="tab" data-tab="${key}" aria-selected="${state.tab === key}">${label}<span class="mono">${n}</span></button>`;
        }).join('');
        const rows = all.filter(o => state.tab === 'All' || o.kind === state.tab).map(o => {
            const status = String(o.status || '').toUpperCase();
            const sub = state.tab === 'All' ? [o.kind, o.sub].filter(Boolean).join(' · ') : o.sub;
            return `<div class="ioc">
                <div class="ioc-value-wrap"><span class="ioc-value" title="${esc(o.copy)}">${esc(o.value)}</span>${sub ? `<span class="ioc-type">${esc(sub)}</span>` : ''}</div>
                ${status ? `<span class="ioc-status${HOT_STATUSES.includes(status) ? ' hot' : ''}">${esc(status)}</span>` : '<span></span>'}
                <button class="icon-btn" type="button" data-copy="${esc(o.copy)}" aria-label="Copy ${esc(o.copy)}" title="Copy">${ICON_COPY}</button>
            </div>`;
        }).join('');
        return `<section id="indicators" aria-label="Indicators">
            <div class="ioc-head" role="tablist"><h2>Indicators</h2>${tabHtml}</div>
            ${rows || '<div class="ioc-empty">No indicators recorded yet.</div>'}
        </section>`;
    }

    // ---------- Views ----------

    function renderDashboard(model) {
        main.innerHTML = headlineHtml(model)
            + chainHtml(model, { hint: 'Click a tactic to filter the timeline' })
            + `<div class="body-grid">${timelineHtml(model)}
                <div class="right-col">${actionsHtml()}${movesHtml()}${indicatorsHtml()}</div></div>`;
    }

    function renderSetup(model) {
        const c = state.campaign;
        const team = c.team || {};
        const done1 = !!(c.operation_name && c.operation_name !== 'New Operation');
        const done2 = !!(team.name || (team.members || []).length);
        const active = !done1 ? 1 : !done2 ? 2 : 3;
        const stepNum = n => `<div class="step-num ${n < active || (n === 1 && done1) || (n === 2 && done2) ? 'done' : n === active ? 'active' : ''}">${(n === 1 && done1) || (n === 2 && done2) ? '✓' : n}</div>`;

        const step1 = active === 1
            ? `<form class="step-box" data-form="operation">
                    <div class="form-row">
                        <label class="field">Operation name<input name="operation_name" required autocomplete="off" placeholder="e.g. Exercise COLD CURRENT"></label>
                        <label class="field">Subtitle<input name="subtitle" autocomplete="off" placeholder="e.g. Organisation · exercise type" value="${esc(c.subtitle === 'Incident Response' ? '' : c.subtitle)}"></label>
                    </div>
                    <div class="step-actions"><button class="btn-primary" type="submit">Save and continue</button>
                    <span class="step-note">Status starts as <strong>Setup</strong>; change it any time on the Admin page.</span></div>
               </form>`
            : `<div class="step-desc">${esc(c.operation_name)}${c.subtitle ? ' · ' + esc(c.subtitle) : ''}</div>`;

        const step2 = active === 2
            ? `<form class="step-box" data-form="team">
                    <div class="form-row">
                        <label class="field">Team name<input name="team_name" autocomplete="off" placeholder="e.g. Blue Cell 3"></label>
                        <label class="field">Analysts, comma separated<input name="members" autocomplete="off" placeholder="e.g. A. Reyes, K. Osei"></label>
                    </div>
                    <div class="step-actions"><button class="btn-primary" type="submit">Save and continue</button></div>
               </form>`
            : done2 ? `<div class="step-desc">${esc(team.name || 'Team')}${(team.members || []).length ? ' · ' + plural(team.members.length, 'analyst', 'analysts') : ''}</div>` : '';

        const step3 = active === 3
            ? `<div class="step-box"><div class="step-actions" style="margin-top:0">
                    <button class="btn-primary" type="button" data-open-drawer>Add the first event</button>
                    <span class="step-note">Or press <kbd>N</kbd> on the dashboard at any time. Indicators and next actions can be added on the Admin page.</span>
               </div></div>`
            : '';

        const step = (n, title, desc, body, last) => `
            <div class="step-marker">${stepNum(n)}${last ? '' : '<div class="step-line"></div>'}</div>
            <div class="step${n === active ? ' active' : ''}">
                <div class="step-title">${title}</div>
                ${n >= active ? `<div class="step-desc">${desc}</div>` : ''}
                ${body}
            </div>`;

        main.innerHTML = `<section class="setup" aria-label="Set up the operation">
                <h1>Set up the operation</h1>
                <p class="setup-intro">Three steps, about two minutes. The dashboard fills in as the team records findings.</p>
                <div class="steps">
                    ${step(1, 'Name the operation', 'Shown on every page and on the wall display.', step1)}
                    ${step(2, 'Add the team', 'Name the cell and its analysts so every finding shows who recorded it.', step2)}
                    ${step(3, 'Record the first finding', 'Log a timeline event, an indicator or a next action.', step3, true)}
                </div>
            </section>`
            + chainHtml(model, { hint: 'Tactics fill in as techniques are recorded', allNotSeen: true, disabled: true });
        const first = main.querySelector('form input');
        if (first) first.focus();
    }

    function renderWall(model) {
        const c = state.campaign;
        const latest = model.dated.slice(0, 4);
        const open = (state.data.recommendations || []).filter(r => r.status !== 'completed').slice(0, 5);
        const events = latest.map(x => {
            const sev = sevOf(x.e);
            return `<div class="wall-event">
                <span class="mono">${x.when.hasTime ? dayLabel(x.when.date) + ' ' + zulu(x.when.date) : dayLabel(x.when.date)}</span>
                <div><div class="wall-event-title">${esc(x.e.title || '')}</div>
                <span class="sev-label" style="color:${sev.color}">${esc(sev.label)}</span></div>
            </div>`;
        }).join('') || '<div class="timeline-empty">No timeline events yet.</div>';
        const actions = open.map(r => `<div class="wall-action"><span>${monoHtml(r.text)}</span></div>`).join('')
            || '<div class="panel-empty">No open actions.</div>';

        main.innerHTML = `<div class="wall-top">
                <strong>${esc(c.operation_name || 'Spotter')}</strong>
                <span>${[c.subtitle ? esc(c.subtitle) : '', c.status ? esc(statusWord(c.status)) : ''].filter(Boolean).join(' · ')}</span>
                <span class="spacer"></span>
                <span class="mono" id="wallClock"></span>
            </div>`
            + headlineHtml(model)
            + chainHtml(model, { hint: '', disabled: true })
            + `<div class="wall-grid">
                <section><h2>Latest events</h2>${events}</section>
                <section class="actions"><div class="section-head actions-head"><h2>Next actions</h2></div><div class="actions-list">${actions}</div></section>
            </div>
            <p class="wall-exit">Press Esc to leave the wall display.</p>`;
        updateClock();
    }

    function render() {
        const model = buildModel();
        document.body.classList.toggle('wall', state.wall && !model.empty);
        renderTopbar(model);
        if (model.empty) renderSetup(model);
        else if (state.wall) renderWall(model);
        else renderDashboard(model);
    }

    // ---------- Data ----------

    async function getJson(url) {
        const r = await fetch(url + (url.includes('?') ? '&' : '?') + 'nocache=' + Date.now());
        if (!r.ok) throw new Error(url + ' ' + r.status);
        return r.json();
    }

    async function loadAll() {
        const [data, campaign, stats] = await Promise.all([getJson('/api/data'), getJson('/api/campaign'), getJson('/api/stats')]);
        state.data = data; state.campaign = campaign; state.stats = stats;
        if (state.tactic && !buildModel().chain.some(t => t.id === state.tactic)) state.tactic = null;
    }

    async function refreshIfChanged() {
        try {
            const stats = await getJson('/api/stats');
            const changed = !state.stats || stats.updated_at !== state.stats.updated_at;
            state.stats = stats;
            const typing = document.activeElement && document.activeElement.closest('form');
            if (changed && !typing && !state.pending.size) { await loadAll(); render(); }
            else updateClock();
        } catch (e) { /* server briefly unavailable; try again next tick */ }
    }

    // ---------- Actions ----------

    function toast(label, value, action) {
        toastEl.innerHTML = esc(label) + (value ? ` <span class="mono">${esc(value.length > 24 ? value.slice(0, 22) + '…' : value)}</span>` : '');
        if (action) {
            const btn = document.createElement('button');
            btn.type = 'button'; btn.textContent = action.label;
            btn.addEventListener('click', () => { toastEl.hidden = true; action.run(); });
            toastEl.appendChild(btn);
        }
        toastEl.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { toastEl.hidden = true; }, action ? 8000 : 1800);
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) {
            // Clipboard API needs HTTPS or localhost; fall back for plain HTTP on a LAN
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        toast('Copied', text);
    }

    async function toggleAction(idx) {
        const rec = state.data.recommendations[idx];
        if (!rec || state.pending.has(idx)) return;
        const status = rec.status === 'completed' ? 'active' : 'completed';
        state.pending.add(idx); render();
        try {
            const r = await fetch('/api/recommendations/' + idx, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status, text: rec.text })
            });
            state.pending.delete(idx);
            if (r.status === 409) {
                await loadAll(); render();
                toast('Someone else changed the actions. Reloaded.');
                return;
            }
            if (!r.ok) throw new Error(r.status);
            rec.status = status;
            state.stats = await getJson('/api/stats');
            render();
            toast(status === 'completed' ? 'Marked done' : 'Marked open');
        } catch (e) {
            state.pending.delete(idx); render();
            toast('Could not save. Check the server and try again.');
        }
    }

    async function saveSetup(form) {
        const f = new FormData(form);
        const campaign = JSON.parse(JSON.stringify(state.campaign));
        if (form.dataset.form === 'operation') {
            const name = String(f.get('operation_name') || '').trim();
            if (!name) return;
            campaign.operation_name = name;
            campaign.subtitle = String(f.get('subtitle') || '').trim();
            if (!campaign.status || campaign.status === 'ACTIVE') campaign.status = 'SETUP';
        } else {
            const members = String(f.get('members') || '').split(',').map(s => s.trim()).filter(Boolean);
            campaign.team = Object.assign({}, campaign.team, { name: String(f.get('team_name') || '').trim(), members });
            if (!campaign.team.name && !members.length) campaign.team.name = 'Team';
        }
        const button = form.querySelector('button[type=submit]');
        button.disabled = true;
        try {
            const r = await fetch('/api/campaign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(campaign) });
            if (!r.ok) throw new Error(r.status);
            state.campaign = campaign;
            render();
        } catch (e) {
            button.disabled = false;
            toast('Could not save. Check the server and try again.');
        }
    }

    main.addEventListener('click', e => {
        const t = e.target.closest('[data-tactic],[data-clear-filter],[data-tab],[data-copy],[data-rec]');
        if (!t) return;
        if (t.hasAttribute('data-tactic')) {
            const id = t.dataset.tactic;
            state.tactic = state.tactic === id ? null : id;
            render();
        } else if (t.hasAttribute('data-clear-filter')) {
            state.tactic = null; render();
        } else if (t.hasAttribute('data-tab')) {
            state.tab = t.dataset.tab; render();
            const again = main.querySelector(`[data-tab="${state.tab}"]`);
            if (again) again.focus();
        } else if (t.hasAttribute('data-copy')) {
            copyText(t.dataset.copy);
        } else if (t.hasAttribute('data-rec')) {
            toggleAction(+t.dataset.rec);
        }
    });

    main.addEventListener('submit', e => {
        const form = e.target.closest('form[data-form]');
        if (!form) return;
        e.preventDefault();
        saveSetup(form);
    });

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && state.wall) location.href = '/';
    });

    // ---------- Add event drawer ----------

    const drawer = document.getElementById('drawer');
    const form = document.getElementById('eventForm');
    const formError = document.getElementById('formError');
    const LOGGED_BY_KEY = 'spotter.loggedBy';
    let drawerOpener = null;

    const utcStamp = d => MONTHS[d.getUTCMonth()] + ' ' + d.getUTCDate() + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());

    function fillTacticOptions() {
        const select = document.getElementById('tacticSelect');
        const chainIds = buildModel().chain.map(t => t.id).filter(Boolean);
        const rest = Object.keys(TACTICS).filter(id => !chainIds.includes(id));
        const option = id => `<option value="${id}">${esc(TACTICS[id])} (${id})</option>`;
        select.innerHTML = '<option value="">Not mapped yet</option>'
            + chainIds.map(option).join('')
            + (rest.length ? `<optgroup label="Other tactics">${rest.map(option).join('')}</optgroup>` : '');
    }

    function fillTeamList() {
        const members = ((state.campaign.team || {}).members || []).map(m => String(m).replace(/^[^:]{1,12}:\s*/, ''));
        document.getElementById('teamList').innerHTML = members.map(m => `<option value="${esc(m)}">`).join('');
    }

    function updateWhenNow() {
        document.getElementById('whenNow').textContent = utcStamp(new Date()) + 'Z  (' + dtg(new Date()) + ')';
    }

    function showWhen() {
        const mode = form.elements.when.value;
        document.getElementById('whenNow').hidden = mode !== 'now';
        document.getElementById('whenEarlier').hidden = mode !== 'earlier';
    }

    function setError(msg, field) {
        form.querySelectorAll('[aria-invalid]').forEach(el => el.removeAttribute('aria-invalid'));
        formError.textContent = msg || '';
        formError.hidden = !msg;
        if (field) { field.setAttribute('aria-invalid', 'true'); field.focus(); }
    }

    function openDrawer(opener) {
        if (!state.data || state.wall) return;
        drawerOpener = opener || document.activeElement;
        form.reset();
        setError('');
        fillTacticOptions();
        fillTeamList();
        if (state.tactic) form.elements.tactic.value = state.tactic;
        const now = new Date();
        form.elements.date.value = now.toISOString().slice(0, 10);
        form.elements.clock.value = pad(now.getUTCHours()) + ':' + pad(now.getUTCMinutes());
        form.elements.logged_by.value = localStorage.getItem(LOGGED_BY_KEY) || '';
        updateWhenNow();
        showWhen();
        drawer.hidden = false;
        form.elements.title.focus();
    }

    function closeDrawer() {
        if (drawer.hidden) return;
        drawer.hidden = true;
        if (drawerOpener && document.body.contains(drawerOpener)) drawerOpener.focus();
    }

    function eventFromForm() {
        const f = form.elements;
        const title = f.title.value.trim();
        if (!title) return setError('Give the event a title.', f.title);

        let time = 'TBD';
        if (f.when.value === 'now') {
            time = utcStamp(new Date());
        } else if (f.when.value === 'earlier') {
            const m = f.date.value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
            if (!m) return setError('Pick the date it happened.', f.date);
            const c = f.clock.value.trim().replace(/^(\d{1,2})(\d{2})$/, '$1:$2');
            const t = c.match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
            if (!t) return setError('Enter the time as HH:MM in 24-hour UTC, e.g. 14:05.', f.clock);
            time = MONTHS[+m[2] - 1] + ' ' + (+m[3]) + ' ' + pad(t[1]) + ':' + t[2];
        }

        const tech = f.tech.value.trim().toUpperCase();
        if (tech && !/^T\d{4}(\.\d{3})?$/.test(tech)) return setError('Technique IDs look like T1059 or T1059.001.', f.tech);

        return {
            title, time, tech,
            tactics: f.tactic.value ? '[' + f.tactic.value + ']' : '',
            severity: f.severity.value,
            desc: f.desc.value.trim(),
            impact: f.impact.value.trim(),
            logged_by: f.logged_by.value.trim(),
            confirmed: !f.unconfirmed.checked
        };
    }

    async function submitEvent() {
        setError('');
        const event = eventFromForm();
        if (!event) return;
        const button = form.querySelector('button[type=submit]');
        button.disabled = true;
        try {
            const r = await fetch('/api/timeline', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(event)
            });
            const body = await r.json().catch(() => ({}));
            if (!r.ok) { setError(body.error || 'Could not save the event.'); return; }
            if (event.logged_by) localStorage.setItem(LOGGED_BY_KEY, event.logged_by);
            else localStorage.removeItem(LOGGED_BY_KEY);
            const saved = body.event;
            const index = body.index;
            if (state.tactic && (saved.tactics || '').indexOf(state.tactic) < 0) state.tactic = null;
            closeDrawer();
            await loadAll();
            state.highlight = index;
            render();
            state.highlight = null;
            const row = main.querySelector('.event.just-added');
            if (row) row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            toast('Added to timeline', saved.title, { label: 'Undo', run: () => undoEvent(index, saved) });
        } catch (e) {
            setError('Could not reach the Spotter server. Check it is running and try again.');
        } finally {
            button.disabled = false;
        }
    }

    async function undoEvent(index, saved) {
        try {
            const r = await fetch('/api/timeline/' + index, {
                method: 'DELETE', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title: saved.title, time: saved.time })
            });
            await loadAll(); render();
            toast(r.ok ? 'Event removed' : 'The timeline changed, so the event was not removed. Edit it on the Admin page.');
        } catch (e) {
            toast('Could not reach the server to undo.');
        }
    }

    form.addEventListener('submit', e => { e.preventDefault(); submitEvent(); });
    form.addEventListener('change', e => { if (e.target.name === 'when') showWhen(); });
    form.addEventListener('keydown', e => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submitEvent(); }
    });

    document.addEventListener('click', e => {
        const open = e.target.closest('[data-open-drawer]');
        if (open) { e.preventDefault(); openDrawer(open); return; }
        if (e.target.closest('[data-close-drawer]')) closeDrawer();
    });

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && !drawer.hidden) { e.stopImmediatePropagation(); closeDrawer(); return; }
        const typing = e.target.closest && e.target.closest('input, textarea, select, [contenteditable]');
        if ((e.key === 'n' || e.key === 'N') && !typing && !e.ctrlKey && !e.metaKey && !e.altKey && drawer.hidden && !state.wall) {
            e.preventDefault();
            openDrawer(document.getElementById('addEventBtn'));
        }
    }, true);

    setInterval(() => { if (!drawer.hidden) updateWhenNow(); }, 15000);

    // ---------- Start ----------

    loadAll().then(render).catch(err => {
        main.innerHTML = '<p class="loading">Could not load the operation. Is the Spotter server running?</p>';
        console.error(err);
    });
    setInterval(updateClock, 30000);
    setInterval(refreshIfChanged, 30000);
})();
