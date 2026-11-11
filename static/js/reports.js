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

const searchInput = document.getElementById('searchInput');
searchInput.value = new URLSearchParams(location.search).get('q') || '';
searchInput.addEventListener('input', applyFilters);
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
