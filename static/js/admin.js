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
    const dateMatch = timeStr.match(/([A-Z]+)\s*(\d+)/i);
    let isoDate = '';
    if (dateMatch) {
        const months = {JAN:0,FEB:1,MAR:2,APR:3,MAY:4,JUN:5,JUL:6,AUG:7,SEP:8,OCT:9,NOV:10,DEC:11};
        const mo = months[dateMatch[1].toUpperCase().slice(0,3)];
        if (mo !== undefined) {
            const d = new Date(2026, mo, parseInt(dateMatch[2]));
            isoDate = d.toISOString().split('T')[0];
        }
    }
    const timeOnly = timeStr.replace(/[A-Z]+\s*\d+\s*/i, '').trim();
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
