// Builds the Spotter navigation rail. Each page includes:
//   <nav class="sidebar" id="app-nav" data-active="dashboard"></nav>
//   <script src="/static/brand.js"></script>
(function () {
    const icon = (body) =>
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

    const LOGO = `<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
        <circle cx="16" cy="16" r="10.5"/>
        <path d="M16 2.5v5M16 24.5v5M2.5 16h5M24.5 16h5"/>
        <path d="M16 9.5c2.7 2.9 2.7 10.1 0 13-2.7-2.9-2.7-10.1 0-13z" fill="currentColor" stroke="none"/>
    </svg>`;

    const ITEMS = [
        { id: 'dashboard', href: '/', label: 'Dashboard',
          icon: icon('<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>') },
        { id: 'network-map', href: '/network-map', label: 'Network Map',
          icon: icon('<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M10.8 7.2 6.2 16.8M13.2 7.2l4.6 9.6M7.5 19h9"/>') },
        { id: 'reports', href: '/reports', label: 'IR Reports',
          icon: icon('<path d="M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>') },
        { id: 'admin', href: '/admin', label: 'Admin',
          icon: icon('<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2" fill="var(--surface-0)"/><circle cx="15" cy="12" r="2" fill="var(--surface-0)"/><circle cx="8" cy="18" r="2" fill="var(--surface-0)"/>') }
    ];

    const nav = document.getElementById('app-nav');
    if (!nav) return;
    const active = nav.dataset.active;
    nav.innerHTML =
        `<a class="brand" href="/" title="Spotter">${LOGO}<span class="brand-word">SPOTTER</span></a>` +
        ITEMS.map(i =>
            `<a href="${i.href}" class="sidebar-item${i.id === active ? ' active' : ''}" title="${i.label}">${i.icon}<span>${i.label}</span></a>`
        ).join('');
})();
