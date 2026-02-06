/**
 * Base template logic for TechScan
 * Handles Theme, Navigation, Animations, Global Utilities
 */

// Global API Fetch Polyfill
(function () {
    if (!window.apiFetch) {
        window.apiFetch = async function (path, opts = {}) {
            const r = await fetch(path, opts);
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        };
    }
})();

// Theme toggle
(function () {
    const THEME_KEY = 'ts-theme';
    const themeBtn = document.getElementById('theme-toggle');
    requestAnimationFrame(() => document.body.classList.add('theme-transition'));
    const applyTheme = (mode) => {
        document.body.classList.toggle('light', mode === 'light');
        if (themeBtn) themeBtn.textContent = mode === 'light' ? '🌚' : '🌙';
    };
    applyTheme(localStorage.getItem(THEME_KEY) || 'dark');
    if (themeBtn) {
        themeBtn.addEventListener('click', () => {
            const cur = document.body.classList.contains('light') ? 'light' : 'dark';
            const next = cur === 'light' ? 'dark' : 'light';
            localStorage.setItem(THEME_KEY, next);
            applyTheme(next);
        });
    }
})();

// Mobile navigation toggle
(function () {
    const nav = document.querySelector('.ts-nav');
    const toggle = document.querySelector('.ts-nav-toggle');
    if (!nav || !toggle) return;
    const closeNav = () => {
        nav.classList.remove('nav-open');
        toggle.setAttribute('aria-expanded', 'false');
    };
    toggle.addEventListener('click', (evt) => {
        evt.stopPropagation();
        const open = nav.classList.toggle('nav-open');
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('click', (evt) => {
        if (!nav.contains(evt.target)) closeNav();
    });
    const mq = window.matchMedia('(max-width: 820px)');
    const handleChange = (evt) => { if (!evt.matches) closeNav(); };
    if (mq.addEventListener) { mq.addEventListener('change', handleChange); }
    else if (mq.addListener) { mq.addListener(handleChange); }
    nav.querySelectorAll('.ts-nav-links a').forEach((link) => {
        link.addEventListener('click', closeNav);
    });
})();

// Auto active state for nav links with smooth transition
(function () {
    const path = location.pathname.replace(/\/$/, '');
    document.querySelectorAll('.ts-nav-links a').forEach(a => {
        const href = a.getAttribute('href');
        if (!href) return;
        const norm = href.replace(/\/$/, '');
        if (norm && (path === norm || (path.startsWith(norm) && norm !== '/' && path.split('/').length === norm.split('/').length))) {
            a.classList.add('active');
        }
    });
})();

// Page load animation - add fade-in class to main content
(function () {
    const main = document.querySelector('main.container');
    if (main) {
        // Ensure animation plays on page load
        main.style.opacity = '0';
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                main.style.opacity = '';
                main.classList.add('page-loaded');
            });
        });
    }
})();

// Progressive reveal for grid items (if present)
(function () {
    const grids = document.querySelectorAll('.tech-grid, .domain-grid, .category-grid, .dashboard-wrapper > *');
    if (!grids.length) return;

    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
                    setTimeout(() => {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }, index * 50); // 50ms stagger
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        grids.forEach((grid) => {
            const items = grid.children;
            Array.from(items).forEach((item, i) => {
                item.style.opacity = '0';
                item.style.transform = 'translateY(20px)';
                item.style.transition = 'opacity 0.4s ease-out, transform 0.4s cubic-bezier(0.22, 0.72, 0.18, 0.99)';
                observer.observe(item);
            });
        });
    }
})();

// Enhanced Ambient Orbs for liquid glass effect
(function () {
    const layer = document.querySelector('.ts-caustic-layer');
    if (!layer) return;
    if (layer.dataset.orbsInit === '1') return; // prevent duplicates
    layer.dataset.orbsInit = '1';

    const rand = (min, max) => Math.random() * (max - min) + min;

    // Ambient orb configurations - colors that work with liquid glass - INCREASED SIZE AND OPACITY
    const orbConfigs = [
        { color: 'rgba(167, 139, 250, 0.6)', size: 500, x: 15, y: 20 },  // purple
        { color: 'rgba(96, 165, 250, 0.55)', size: 450, x: 75, y: 15 },  // blue
        { color: 'rgba(34, 211, 238, 0.5)', size: 400, x: 85, y: 70 },   // cyan
        { color: 'rgba(244, 114, 182, 0.45)', size: 380, x: 20, y: 75 }, // pink
        { color: 'rgba(129, 140, 248, 0.55)', size: 480, x: 50, y: 50 }, // indigo
        { color: 'rgba(52, 211, 153, 0.45)', size: 420, x: 60, y: 85 },  // emerald
    ];

    orbConfigs.forEach((config, i) => {
        const orb = document.createElement('div');
        orb.className = 'ambient-orb drifting';

        // Size
        orb.style.width = config.size + 'px';
        orb.style.height = config.size + 'px';

        // Position
        orb.style.left = config.x + '%';
        orb.style.top = config.y + '%';
        orb.style.transform = 'translate(-50%, -50%)';

        // Color
        orb.style.background = `radial-gradient(circle, ${config.color} 0%, transparent 70%)`;

        // Animation timing - each orb has different timing for organic feel
        const driftDuration = rand(15, 30);
        const pulseDuration = rand(6, 12);
        const minOpacity = rand(0.3, 0.5);
        const maxOpacity = rand(0.6, 0.9);
        const delay = rand(-5, 5);

        orb.style.setProperty('--drift-duration', driftDuration + 's');
        orb.style.setProperty('--pulse-duration', pulseDuration + 's');
        orb.style.setProperty('--min-opacity', minOpacity);
        orb.style.setProperty('--max-opacity', maxOpacity);
        orb.style.animationDelay = delay + 's';

        layer.appendChild(orb);
    });

    // Add a few spinning orbs for extra dynamism
    const spinningOrbs = [
        { color: 'rgba(139, 92, 246, 0.3)', size: 200, centerX: 30, centerY: 40, orbitRadius: 150 },
        { color: 'rgba(59, 130, 246, 0.25)', size: 180, centerX: 70, centerY: 60, orbitRadius: 120 },
    ];

    spinningOrbs.forEach((config, i) => {
        const container = document.createElement('div');
        container.className = 'orb-container';
        container.style.left = config.centerX + '%';
        container.style.top = config.centerY + '%';
        container.style.setProperty('--orbit-radius', config.orbitRadius + 'px');
        container.style.setProperty('--orbit-duration', rand(25, 40) + 's');
        container.style.animationDelay = rand(-10, 0) + 's';

        const orb = document.createElement('div');
        orb.className = 'ambient-orb spinning';
        orb.style.width = config.size + 'px';
        orb.style.height = config.size + 'px';
        orb.style.background = `radial-gradient(circle, ${config.color} 0%, transparent 70%)`;
        orb.style.setProperty('--pulse-duration', rand(5, 10) + 's');
        orb.style.setProperty('--min-opacity', 0.2);
        orb.style.setProperty('--max-opacity', 0.6);

        container.appendChild(orb);
        layer.appendChild(container);
    });
})();

// Footer year stamp
(function () {
    const yearEl = document.getElementById('ts-footer-year');
    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }
})();
