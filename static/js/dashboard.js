async function loadAll() {
    try {
        const [campaignResp, dataResp, statsResp] = await Promise.all([
            fetch('/api/campaign?nocache=' + Date.now()),
            fetch('/api/data?nocache=' + Date.now()),
            fetch('/api/stats?nocache=' + Date.now())
        ]);
        const campaign = await campaignResp.json();
        const data = await dataResp.json();
        const stats = await statsResp.json();
        renderCampaign(campaign);
        renderStats(stats);
        renderData(data);
    } catch(e) {
        console.log('Error loading:', e);
    }
}

function renderCampaign(c) {
    document.title = (c.operation_name ? c.operation_name + ' · ' : '') + 'Spotter';
    document.getElementById('operationName').textContent = c.operation_name || '';
    document.getElementById('operationSubtitle').textContent = c.subtitle || '';
    document.getElementById('teamName').textContent = c.team?.name || '';
    document.getElementById('teamDesc').textContent = c.team?.description || '';
    document.getElementById('teamMembers').innerHTML = (c.team?.members || []).join(' | ');
    document.getElementById('dashboardTitle').textContent = c.dashboard_title || '';
    document.getElementById('operationDesc').textContent = c.description || '';

    if (c.alert_banner && c.alert_banner.title) {
        document.getElementById('alertBanner').style.display = 'block';
        document.getElementById('alertTitle').textContent = c.alert_banner.title;
        document.getElementById('alertMessage').textContent = c.alert_banner.message || '';
    }

    if (c.stats) {
        document.getElementById('statIocLabel').textContent = c.stats.ioc_label || '';
        document.getElementById('statUsersLabel').textContent = c.stats.users_label || '';
        document.getElementById('statSystemsLabel').textContent = c.stats.systems_label || '';
        document.getElementById('statMitreLabel').textContent = c.stats.mitre_label || '';
        document.getElementById('statStatusLabel').textContent = c.stats.status_label || '';
    }

    document.getElementById('killChainTitle').textContent = c.kill_chain_title || '';
    const phasesContainer = document.getElementById('killChainPhases');
    if (c.kill_chain_phases && c.kill_chain_phases.length) {
        phasesContainer.innerHTML = c.kill_chain_phases.map(p =>
            `<div class="wolf-step ${p.status || ''}">${p.name}</div>`
        ).join('');
    }

    if (c.panels) {
        document.getElementById('suspiciousIpsTitle').textContent = c.panels.suspicious_ips_title || '';
        document.getElementById('phishingDomainsTitle').textContent = c.panels.phishing_domains_title || '';
    }

    document.getElementById('threatIntelTitle').textContent = c.threat_intel_title || '';
    document.getElementById('recommendationsTitle').textContent = c.recommendations_title || '';
}

function renderStats(stats) {
    document.getElementById('statIocValue').textContent = stats.active_iocs ?? 0;
    document.getElementById('statUsersValue').textContent = stats.compromised_users ?? 0;
    document.getElementById('statSystemsValue').textContent = stats.affected_systems ?? 0;
    document.getElementById('statMitreValue').textContent = stats.mitre_techniques ?? 0;
    document.getElementById('statStatusValue').textContent = stats.status || '';
}

function renderData(data) {
    const timeline = data.timeline || [];
    const ips = data.suspicious_ips || [];
    const domains = data.phishing_domains || [];
    const threatIntel = data.threat_intel || [];
    const recommendations = data.recommendations || [];

    renderTimeline(timeline);
    renderIPs(ips);
    renderDomains(domains);
    renderThreatIntel(threatIntel);
    renderRecommendations(recommendations);
}

function renderTimeline(events) {
    const container = document.getElementById('timelineContainer');
    if (!events.length) { container.innerHTML = '<div style="color:var(--text-muted);padding:20px;">No timeline events</div>'; return; }

    const parseDate = (time) => {
        if (!time) return null;
        const m = time.match(/([A-Z]+)\s*(\d+)/i);
        if (m) {
            const month = m[1].toUpperCase();
            const shortMonth = month.length > 3 ? month.slice(0,3) : month;
            return shortMonth + ' ' + parseInt(m[2]);
        }
        return null;
    };

    const grouped = {};
    let lastDate = null;
    events.forEach(e => {
        const time = e.time || '';
        const date = parseDate(time);
        if (date) lastDate = date;
        const group = time === 'TBD' ? 'TBD' : (date || lastDate || 'Other');
        if (!grouped[group]) grouped[group] = [];
        grouped[group].push(e);
    });

    const monthOrder = { 'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4, 'MAY': 5, 'JUN': 6, 'JUL': 7, 'AUG': 8, 'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12 };
    const dateOrder = (a) => {
        if (a === 'TBD') return -1;
        const m = a.match(/([A-Z]+)\s*(\d+)/i);
        if (m) return -((monthOrder[m[1].toUpperCase()] || 0) * 100 + parseInt(m[2]));
        return 0;
    };

    const sortedDates = Object.keys(grouped).sort((a,b) => dateOrder(a) - dateOrder(b));
    const sortByTime = (a, b) => {
        const ta = a.time || '', tb = b.time || '';
        if (ta === 'TBD' && tb !== 'TBD') return 1;
        if (tb === 'TBD' && ta !== 'TBD') return -1;
        const timeA = ta.match(/(\d+):(\d+)/), timeB = tb.match(/(\d+):(\d+)/);
        if (timeA && timeB) return (parseInt(timeB[1])*60 + parseInt(timeB[2])) - (parseInt(timeA[1])*60 + parseInt(timeA[2]));
        return 0;
    };

    let html = '';
    sortedDates.forEach(date => {
        const dayEvents = grouped[date].sort(sortByTime);
        html += `<div style="margin:25px 0 15px 0;padding-bottom:10px;border-bottom:2px solid var(--accent);font-family:var(--font-sans);font-size:16px;color:var(--accent);">${date}</div>`;
        html += dayEvents.map(e => {
            const severity = e.severity === 'critical' ? 'var(--critical)' : e.severity === 'high' ? 'var(--high)' : 'var(--medium)';
            const timeOnly = (e.time || '').replace(/[A-Z]+\s*\d+\s*/i, '').trim() || 'TBD';
            return `<div class="event">
                <div class="event-time">${timeOnly}</div>
                <div class="event-content">
                    <div class="event-title" style="color:${severity};">${e.title || ''}
                        <span class="event-tech">${e.tech || ''}</span>
                        <span class="event-tactic">${e.tactics || ''}</span>
                    </div>
                    <div class="event-desc">${e.desc || ''}</div>
                    <div class="event-impact" style="color:${severity};">${e.impact || ''}</div>
                </div>
            </div>`;
        }).join('');
    });
    container.innerHTML = html;
}

function renderIPs(ips) {
    const list = document.getElementById('ipList');
    if (!ips.length) { list.innerHTML = '<li style="color:var(--text-muted);">No IPs tracked</li>'; return; }
    list.innerHTML = ips.map(ip => {
        const isActive = ip.status === 'ACTIVE';
        const bg = isActive ? 'var(--critical-soft)' : 'var(--surface-1)';
        const color = isActive ? 'var(--critical)' : 'var(--text-muted)';
        return `<li style="background:${bg};"><span class="ioc-ip" style="color:${color};font-weight:bold;">${ip.ip} ${ip.label ? ' ' + ip.label : ''}</span><span class="ioc-type" style="background:${color};${!isActive?'opacity:0.5':''}">${ip.type}</span></li>`;
    }).join('');
}

function renderDomains(domains) {
    const list = document.getElementById('domainList');
    if (!domains.length) { list.innerHTML = '<li style="color:var(--text-muted);">No domains tracked</li>'; return; }
    list.innerHTML = domains.map(d =>
        `<li><span class="ioc-ip" style="color:var(--medium);">${d.domain}</span><span class="ioc-type">${d.type}</span></li>`
    ).join('');
}

function renderThreatIntel(items) {
    const container = document.getElementById('threatIntelList');
    if (!items.length) { container.innerHTML = '<div style="color:var(--text-muted);">No threat intel</div>'; return; }
    container.innerHTML = items.map(item =>
        `<div class="rec-item">
            <div class="rec-num">&#8213;</div>
            <div class="rec-text">${item.text}</div>
            <div class="rec-mitre">${item.mitre || ''}</div>
        </div>`
    ).join('');
}

function renderRecommendations(items) {
    const container = document.getElementById('recommendationsList');
    if (!items.length) { container.innerHTML = '<div style="color:var(--text-muted);">No recommendations</div>'; return; }
    container.innerHTML = items.map(item => {
        const isActive = item.status === 'active';
        return `<div class="rec-item" style="${!isActive ? 'opacity: 0.6;' : ''}">
            <div class="rec-num">${isActive ? '&#8213;' : '&#10003;'}</div>
            <div class="rec-text">${item.text}${!isActive ? ' <strong>(COMPLETED)</strong>' : ''}</div>
            <div class="rec-mitre">${item.mitre || ''}</div>
        </div>`;
    }).join('');
}

document.addEventListener('DOMContentLoaded', loadAll);
