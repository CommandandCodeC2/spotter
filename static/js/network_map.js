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
