/* Extracted from report.html */
(function () {

    function closeEvidenceModal() {
        var modal = document.getElementById('evidenceModal');
        if (modal) {
            modal.classList.remove('active');
        }
    }

    // XSS protection: escape HTML special characters
    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, function (ch) {
            switch (ch) {
                case '&': return '&amp;';
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '"': return '&quot;';
                case "'": return '&#39;';
                default: return ch;
            }
        });
    }

    // Alias for backward compatibility
    const esc = escapeHtml;

    // Tech Icon Helpers
    function techIconHTML(name, version) {
        if (!name) return '';
        let title = version ? `${name} ${version}` : name;

        // Normalize tech name to match local icon filename
        let iconKey = name.toLowerCase().replace(/[^a-z0-9+#]/g, '');

        const iconMap = {
            'react.js': 'react', 'reactjs': 'react',
            'angular.js': 'angular', 'angularjs': 'angular',
            'vue.js': 'vuejs', 'vue': 'vuejs',
            'node.js': 'nodejs', 'nodejs': 'nodejs',
            '.net': 'dotnet', 'asp.net': 'netcore',
            'c++': 'cplusplus', 'cplusplus': 'c++',
            'c#': 'csharp', 'csharp': 'c#',
            'bootstrap': 'bootstrap5',
            'css': 'css3', 'css3': 'css3',
            'html': 'html5', 'html5': 'html5',
            'javascript': 'js', 'js': 'js',
            'typescript': 'typescript',
            'sass': 'sass', 'scss': 'sass',
            'postgresql': 'postgresql', 'postgres': 'postgresql',
            'elasticsearch': 'elastic',
            'tailwind': 'tailwindcss', 'tailwind css': 'tailwindcss'
        };

        if (iconMap[name.toLowerCase()]) {
            iconKey = iconMap[name.toLowerCase()];
        } else if (iconMap[iconKey]) {
            iconKey = iconMap[iconKey];
        }

        const localPath = `/static/icons/tech/${encodeURIComponent(iconKey)}.svg`;
        return `<div class='tech-logo' style='display:inline-block;width:20px;height:20px;min-width:20px;vertical-align:middle;'><img src='${localPath}' alt='${name}' title='${title}' style='width:100%;height:100%;object-fit:contain;' onerror="this.onerror=null;this.parentElement.innerHTML='<div class=\\'tech-icon\\' style=\\'background:'+iconColorFor(this.parentElement.title)+';width:20px;height:20px;font-size:12px;display:flex;align-items:center;justify-content:center;border-radius:4px;color:white;font-weight:bold;\\' title=\\''+this.parentElement.title+'\\'>'+this.parentElement.title.charAt(0).toUpperCase()+'</div>'"/></div>`;
    }

    function iconColorFor(name) {
        if (!name) return '#ccc';
        let hash = 0;
        for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
        const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
        return '#' + '00000'.substring(0, 6 - c.length) + c;
    }

    // Category configuration with proper API names matching Wappalyzer categories
    // Note: Reverse Proxies and SSL/TLS Certificate disabled for 4-4 layout
    const CATEGORIES = [
        { id: 'cms', name: 'CMS', api: 'cms' },
        { id: 'programming', name: 'Programming Language', api: 'programming languages' },
        { id: 'ui', name: 'UI Frameworks', api: 'ui frameworks' },
        { id: 'webframework', name: 'Web Framework', api: 'web frameworks' },
        { id: 'database', name: 'Database', api: 'databases' },
        // { id: 'proxies', name: 'Reverse Proxies', api: 'reverse proxies' },  // disabled
        { id: 'security', name: 'Security', api: 'security' },
        // { id: 'ssl', name: 'SSL/TLS Certificate', api: 'ssl-tls-certificate-authorities' },  // disabled
        { id: 'cdn', name: 'CDN', api: 'cdn' },
        { id: 'os', name: 'Operating System', api: 'operating systems' }
    ];

    // Tech with children - uses exact category names from Wappalyzer
    const TECH_CHILDREN = {
        'wordpress': [
            { name: 'WordPress Plugins', api: 'wordpress plugins' },
            { name: 'WordPress Themes', api: 'wordpress themes' }
        ],
        'drupal': [
            { name: 'Drupal Modules', api: 'drupal modules' }
        ],
        'joomla': [
            { name: 'Joomla Extensions', api: 'joomla extensions' }
        ]
    };

    // Navigation state
    let navStack = [];
    let currentView = null;
    const charts = {};
    const COLORS = ['#22c55e', '#60a5fa', '#fbbf24', '#f472b6', '#a78bfa', '#fb923c'];

    // Escape HTML
    function esc(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // Helper function to delay
    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Initialize charts with staggered API calls to avoid rate limit
    async function init() {
        for (let i = 0; i < CATEGORIES.length; i++) {
            const cat = CATEGORIES[i];
            // Add delay between requests to avoid rate limit (150ms = max 6/sec = 360/min < 60 limit)
            if (i > 0) await delay(150);

            try {
                const res = await fetch(`/api/category/${encodeURIComponent(cat.api)}/technologies`);
                if (!res.ok) {
                    console.error('API error:', cat.id, res.status);
                    continue;
                }
                const data = await res.json();
                const techs = data.technologies || [];

                // Update count
                const total = techs.reduce((sum, t) => sum + (t.count || 0), 0);
                const countEl = document.getElementById(`count-${cat.id}`);
                if (countEl) countEl.textContent = total.toLocaleString();

                // Create chart
                const ctx = document.getElementById(`chart-${cat.id}`);
                if (ctx && techs.length > 0) {
                    charts[cat.id] = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: techs.slice(0, 5).map(t => t.tech?.substring(0, 10) || 'Unknown'),
                            datasets: [{
                                data: techs.slice(0, 5).map(t => t.count),
                                backgroundColor: COLORS,
                                borderRadius: 4
                            }]
                        },
                        options: {
                            indexAxis: 'y',
                            responsive: true,
                            maintainAspectRatio: false,
                            layout: {
                                padding: { right: 35 }
                            },
                            plugins: {
                                legend: { display: false },
                                datalabels: {
                                    anchor: 'end',
                                    align: 'end',
                                    color: 'rgba(255,255,255,0.9)',
                                    font: { size: 9, weight: 'bold' },
                                    formatter: (value) => value?.toLocaleString() || ''
                                }
                            },
                            scales: {
                                x: { display: false },
                                y: {
                                    grid: { display: false },
                                    ticks: { color: 'rgba(255,255,255,0.7)', font: { size: 8 } }
                                }
                            }
                        },
                        plugins: [ChartDataLabels]
                    });
                }
            } catch (err) {
                console.error('Failed to load:', cat.id, err);
            }
        }
    }

    // Open Layer 2 - Category view
    window.openCategory = function (apiName, displayName) {
        navStack = [{ type: 'category', api: apiName, name: displayName }];
        currentView = { type: 'category', api: apiName, name: displayName };

        document.getElementById('layer2Modal').classList.add('active');
        document.getElementById('modal-title').textContent = displayName;
        document.getElementById('layer2BackBtn').textContent = '← Close';

        updateBreadcrumb();
        loadCategoryContent(apiName);
    };

    // Open Tech view - shows websites using this tech
    window.openTech = function (techName) {
        navStack.push({ type: 'tech', name: techName });
        currentView = { type: 'tech', name: techName };

        document.getElementById('modal-title').textContent = techName;
        document.getElementById('layer2BackBtn').textContent = '← Back to Category';

        updateBreadcrumb();
        loadTechContent(techName);
    };

    // Open website detail Layer 3
    window.openWebsite = function (domain) {
        document.getElementById('layer3Modal').classList.add('active');
        document.getElementById('website-title').textContent = domain;
        loadWebsiteTechStack(domain);
    };

    // Update breadcrumb
    function updateBreadcrumb() {
        const container = document.getElementById('breadcrumb');
        let html = '';

        navStack.forEach((item, idx) => {
            if (idx > 0) html += '<span class="breadcrumb-separator">→</span>';
            const isLast = idx === navStack.length - 1;
            html += `<span class="breadcrumb-item ${isLast ? 'active' : ''}" onclick="navigateTo(${idx})">${esc(item.name)}</span>`;
        });

        container.innerHTML = html;
    }

    // Navigate to breadcrumb item
    window.navigateTo = function (idx) {
        if (idx >= navStack.length - 1) return;

        navStack = navStack.slice(0, idx + 1);
        const item = navStack[idx];
        currentView = item;

        document.getElementById('modal-title').textContent = item.name;

        if (item.type === 'category') {
            document.getElementById('layer2BackBtn').textContent = '← Close';
            loadCategoryContent(item.api);
        } else if (item.type === 'tech') {
            document.getElementById('layer2BackBtn').textContent = '← Back to Category';
            loadTechContent(item.name);
        }

        updateBreadcrumb();
    };

    // Handle back button
    window.handleLayer2Back = function () {
        if (navStack.length <= 1) {
            closeAllModals();
        } else {
            navStack.pop();
            const prev = navStack[navStack.length - 1];
            currentView = prev;

            document.getElementById('modal-title').textContent = prev.name;

            if (prev.type === 'category') {
                document.getElementById('layer2BackBtn').textContent = '← Close';
                loadCategoryContent(prev.api);
            } else {
                document.getElementById('layer2BackBtn').textContent = '← Back';
                loadTechContent(prev.name);
            }

            updateBreadcrumb();
        }
    };

    // Load category content
    async function loadCategoryContent(apiName) {
        const content = document.getElementById('modal-content');
        const tabs = document.getElementById('modal-tabs');

        content.innerHTML = '<div class="loading-text">Loading technologies...</div>';
        tabs.innerHTML = '<button class="report-tab active">Technologies</button>';

        try {
            const res = await fetch(`/api/category/${encodeURIComponent(apiName)}/technologies`);
            const data = await res.json();
            const techs = data.technologies || [];

            if (techs.length === 0) {
                content.innerHTML = '<div class="loading-text">No technologies found in this category</div>';
                return;
            }

            content.innerHTML = `
        <div class="report-list">
          ${techs.map(t => `
            <div class="report-item" onclick="openTech('${esc(t.tech)}')">
              <span class="report-item-name">${esc(t.tech)}</span>
              <span class="report-item-count">${(t.count || 0).toLocaleString()} sites</span>
              <span class="report-item-arrow">→</span>
            </div>
          `).join('')}
        </div>
      `;
        } catch (err) {
            content.innerHTML = '<div class="loading-text">Error loading data. Please try again.</div>';
            console.error('Load category error:', err);
        }
    }

    // Load tech content - websites + child tabs
    async function loadTechContent(techName) {
        const content = document.getElementById('modal-content');
        const tabs = document.getElementById('modal-tabs');
        const techLower = techName.toLowerCase();
        const children = TECH_CHILDREN[techLower] || [];

        // Build tabs
        let tabsHtml = '<button class="report-tab active" onclick="switchTechTab(\'websites\')">Websites</button>';
        children.forEach((child, idx) => {
            tabsHtml += `<button class="report-tab" onclick="switchTechTab('child-${idx}', '${esc(child.api)}')">${esc(child.name)}</button>`;
        });
        tabs.innerHTML = tabsHtml;

        // Load websites
        content.innerHTML = '<div class="loading-text">Loading websites...</div>';

        try {
            // Try the tech domains API
            const res = await fetch(`/api/tech/${encodeURIComponent(techName)}/domains`);
            const data = await res.json();
            let domains = data.domains || [];

            if (domains.length === 0) {
                content.innerHTML = '<div class="loading-text">No websites found using this technology</div>';
                return;
            }

            // Show all domains (scrollable modal) with numbering
            content.innerHTML = `
        <div class="report-list">
          <div style="margin-bottom:0.5rem;color:rgba(255,255,255,0.6);font-size:0.85rem;">${domains.length} websites using ${techName}</div>
          ${domains.map((d, idx) => {
                const domain = typeof d === 'string' ? d : (d.domain || d.name || d);
                return `
              <div class="report-item" onclick="openWebsite('${esc(domain)}')">
                <span style="color:rgba(255,255,255,0.4);font-size:0.8rem;min-width:35px;margin-right:8px;">${idx + 1}.</span>
                <span class="report-item-name">${esc(domain)}</span>
                <span class="report-item-arrow">→</span>
              </div>
            `;
            }).join('')}
        </div>
      `;
        } catch (err) {
            content.innerHTML = '<div class="loading-text">Error loading websites. Please try again.</div>';
            console.error('Load tech error:', err);
        }
    }

    // Switch tech tab
    window.switchTechTab = async function (tabId, childApi) {
        document.querySelectorAll('.report-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');

        const content = document.getElementById('modal-content');

        if (tabId === 'websites') {
            loadTechContent(currentView.name);
            return;
        }

        // Load child category
        content.innerHTML = '<div class="loading-text">Loading...</div>';

        try {
            const res = await fetch(`/api/category/${encodeURIComponent(childApi)}/technologies`);
            const data = await res.json();
            const techs = data.technologies || [];

            if (techs.length === 0) {
                content.innerHTML = '<div class="loading-text">No items found in this category</div>';
                return;
            }

            content.innerHTML = `
        <div class="report-list">
          ${techs.map(t => `
            <div class="report-item" onclick="openTech('${esc(t.tech)}')">
              <span class="report-item-name">${esc(t.tech)}</span>
              <span class="report-item-count">${(t.count || 0).toLocaleString()} sites</span>
              <span class="report-item-arrow">→</span>
            </div>
          `).join('')}
        </div>
      `;
        } catch (err) {
            content.innerHTML = '<div class="loading-text">Error loading data</div>';
        }
    };

    // Load website tech stack
    async function loadWebsiteTechStack(domain) {
        const container = document.getElementById('website-tech-stack');
        container.innerHTML = '<div class="loading-text">Loading tech stack...</div>';

        try {
            const res = await fetch(`/api/domain/${encodeURIComponent(domain)}/detail`);
            const data = await res.json();

            // Extract metadata - use field names that match API response
            const scanData = data.selected_scan || data.latest || data || {};
            // API returns finished_at (epoch timestamp)
            const scanTs = scanData.finished_at || scanData.started_at || data.finished_at || data.started_at || null;
            // API returns payload_bytes
            const payload = scanData.payload_bytes || data.payload_bytes || null;

            // Try multiple response formats for techs
            let techs = [];
            if (scanData.technologies) {
                techs = scanData.technologies;
            } else if (data.technologies) {
                techs = data.technologies;
            } else if (Array.isArray(data)) {
                techs = data;
            }

            // Build metadata header
            let metaHtml = '<div class="website-meta">';
            metaHtml += `
                  <div class="website-meta-item">
                    <div class="website-meta-label">Technologies</div>
                    <div class="website-meta-value">${techs.length}</div>
                  </div>
                `;

            if (scanTs) {
                // API returns epoch in seconds, JS Date needs milliseconds
                const scanDate = new Date(scanTs * 1000);
                const formattedDate = scanDate.toLocaleDateString('id-ID', {
                    day: 'numeric', month: 'short', year: 'numeric'
                });
                metaHtml += `
                      <div class="website-meta-item">
                        <div class="website-meta-label">Last Scan</div>
                        <div class="website-meta-value">${formattedDate}</div>
                      </div>
                    `;
            }

            if (payload) {
                const payloadKB = (payload / 1024).toFixed(1);
                metaHtml += `
                      <div class="website-meta-item">
                        <div class="website-meta-label">Payload</div>
                        <div class="website-meta-value">${payloadKB} KB</div>
                      </div>
                    `;
            }

            // Count categories
            const catSet = new Set();
            techs.forEach(t => {
                if (t.categories && t.categories.length) catSet.add(t.categories[0]);
                else if (t.category) catSet.add(t.category);
            });
            metaHtml += `
                  <div class="website-meta-item">
                    <div class="website-meta-label">Categories</div>
                    <div class="website-meta-value">${catSet.size}</div>
                  </div>
                `;
            metaHtml += '</div>';

            if (techs.length === 0) {
                container.innerHTML = metaHtml + '<div class="loading-text">No technologies detected for this website</div>';
                return;
            }

            // Group by category
            const grouped = {};
            techs.forEach(t => {
                let cat = 'Other';
                if (t.categories && t.categories.length > 0) {
                    cat = Array.isArray(t.categories) ? t.categories[0] : t.categories;
                } else if (t.category) {
                    cat = t.category;
                }
                if (!grouped[cat]) grouped[cat] = [];
                grouped[cat].push(t);
            });

            // Sort categories alphabetically
            const sortedCats = Object.keys(grouped).sort();

            container.innerHTML = metaHtml + sortedCats.map(cat => {
                const items = grouped[cat];
                return `
                      <div class="report-stack-group">
                        <div class="report-stack-title">${esc(cat)} (${items.length})</div>
                        <div>
                          ${items.map(t => {
                    // Build evidence info
                    let evidenceHtml = '';
                    const evidenceTypes = [];
                    if (t.headers) evidenceTypes.push('Headers');
                    if (t.scripts) evidenceTypes.push('Scripts');
                    if (t.meta) evidenceTypes.push('Meta');
                    if (t.html) evidenceTypes.push('HTML');
                    if (t.implies && t.implies.length > 0) evidenceTypes.push('Implied');

                    if (evidenceTypes.length > 0 || t.description || t.website) {
                        evidenceHtml = `<div class="tech-evidence" style="font-size:0.7rem;color:rgba(255,255,255,0.5);margin-top:2px;">`;
                        if (evidenceTypes.length > 0) {
                            evidenceHtml += `<span style="background:rgba(255,255,255,0.1);padding:1px 4px;border-radius:3px;margin-right:4px;">${evidenceTypes.join(', ')}</span>`;
                        }
                        if (t.confidence) {
                            evidenceHtml += `<span style="color:#22c55e;">${t.confidence}%</span>`;
                        }
                        if (t.website) {
                            evidenceHtml += ` <a href="${esc(t.website)}" target="_blank" style="color:#60a5fa;text-decoration:none;">↗</a>`;
                        }
                        evidenceHtml += `</div>`;
                        if (t.description) {
                            evidenceHtml += `<div style="font-size:0.65rem;color:rgba(255,255,255,0.4);margin-top:2px;max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(t.description)}</div>`;
                        }
                    }

                    const iconHtml = techIconHTML(t.name || t.tech, t.version);
                    return `
                              <div class="report-stack-item" style="display:inline-block;margin:3px;padding:6px 10px;background:rgba(255,255,255,0.05);border-radius:6px;vertical-align:top;cursor:pointer;" onclick='showEvidencePopup(${JSON.stringify(t).replace(/'/g, "&#39;")})'>
                                <div style="display:flex;align-items:center;gap:6px;">
                                  ${iconHtml}
                                  <strong>${esc(t.name || t.tech)}</strong>
                                  ${t.version ? `<span class="report-stack-version" style="color:#fbbf24;font-size:0.75rem;margin-left:4px;">v${t.version}</span>` : ''}
                                </div>
                                ${evidenceHtml}
                              </div>
                            `;
                }).join('')}
                        </div>
                      </div>
                    `;
            }).join('');
        } catch (err) {
            container.innerHTML = '<div class="loading-text">Error loading tech stack</div>';
            console.error('Load website error:', err);
        }
    }

    // Close modals
    window.closeAllModals = function () {
        document.getElementById('layer2Modal').classList.remove('active');
        document.getElementById('layer3Modal').classList.remove('active');
        navStack = [];
        currentView = null;
    };

    window.closeLayer3 = function () {
        document.getElementById('layer3Modal').classList.remove('active');
    };

    // Evidence popup functions
    window.showEvidencePopup = function (tech) {
        const modal = document.getElementById('evidenceModal');
        const nameEl = document.getElementById('evidence-tech-name');
        const bodyEl = document.getElementById('evidence-body');

        // Set title with version
        nameEl.textContent = tech.name || tech.tech || 'Technology';
        if (tech.version) {
            nameEl.textContent += ` v${tech.version}`;
        }

        // Build evidence content
        let html = '';

        // Detection sources section
        const sources = [];
        if (tech.headers) sources.push('HTTP Headers');
        if (tech.scripts) sources.push('JavaScript');
        if (tech.meta) sources.push('Meta Tags');
        if (tech.html) sources.push('HTML Content');
        if (tech.implies && tech.implies.length > 0) sources.push('Implied by other tech');

        if (sources.length > 0) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Detection Sources</div>
                    ${sources.map(s => `<span class="evidence-tag source">${esc(s)}</span>`).join('')}
                </div>`;
        }

        // Confidence section
        if (tech.confidence) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Confidence</div>
                    <span class="evidence-tag">${tech.confidence}%</span>
                </div>`;
        }

        // Categories section
        if (tech.categories && tech.categories.length > 0) {
            const cats = Array.isArray(tech.categories) ? tech.categories : [tech.categories];
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Categories</div>
                    ${cats.map(c => `<span class="evidence-tag">${esc(c)}</span>`).join('')}
                </div>`;
        }

        // Description section
        if (tech.description) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Description</div>
                    <p class="evidence-description">${esc(tech.description)}</p>
                </div>`;
        }

        // Website link section
        if (tech.website) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Official Website</div>
                    <a href="${esc(tech.website)}" target="_blank" class="evidence-link">
                        ${esc(tech.website)} ↗
                    </a>
                </div>`;
        }

        // Evidence Artifacts section (pattern, scriptSrc, html snippets + evidence array)
        const evidenceArr = (tech.evidence && tech.evidence.length > 0) ? tech.evidence : [];
        let hasEvidence = evidenceArr.length > 0 || tech.scriptSrc || tech.pattern || tech.match || tech.html || tech.url || tech.certIssuer || tech.scripts;

        if (hasEvidence) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Evidence</div>
                    <p style="font-size:0.8rem;color:rgba(255,255,255,0.5);margin-bottom:0.75rem;">Snippet, headers, or matches we captured as proof of detection.</p>`;

            // If we have evidence array from scan_utils, display it nicely
            if (evidenceArr.length > 0) {
                // Group evidence by source type
                const sourceTypes = [...new Set(evidenceArr.map(e => e.source || 'unknown'))];

                if (sourceTypes.length > 0) {
                    html += `<div class="evidence-tabs">
                            ${sourceTypes.map((src, i) => `<button class="evidence-tab${i === 0 ? ' active' : ''}" onclick="switchEvidenceTab(this, '${src}')">${src}</button>`).join('')}
                        </div>`;
                }

                // Show evidence entries grouped by source
                sourceTypes.forEach((srcType, idx) => {
                    const srcEvidence = evidenceArr.filter(e => (e.source || 'unknown') === srcType);
                    const displayBlock = idx === 0 ? '' : 'display:none;';

                    srcEvidence.forEach(ev => {
                        let content = '';
                        if (ev.url) content += ev.url + '\\n';
                        if (ev.snippet) content += ev.snippet + '\\n';
                        if (ev.value) content += ev.value + '\\n';
                        if (!content && ev.pattern) content = ev.pattern;
                        if (!content) content = JSON.stringify(ev, null, 2);

                        html += `<div class="evidence-code-block" data-evidence="${srcType}" style="${displayBlock}">${esc(content.trim())}</div>`;
                    });
                });
            } else {
                // Fallback to direct fields (pattern, scriptSrc, etc)
                let evidenceTabs = [];
                if (tech.pattern) evidenceTabs.push('pattern');
                if (tech.scriptSrc || tech.scripts) evidenceTabs.push('scriptSrc');
                if (tech.html) evidenceTabs.push('html');
                if (tech.url) evidenceTabs.push('url');
                if (tech.certIssuer) evidenceTabs.push('certIssuer');

                if (evidenceTabs.length > 0) {
                    html += `<div class="evidence-tabs">
                            ${evidenceTabs.map((tab, i) => `<button class="evidence-tab${i === 0 ? ' active' : ''}" onclick="switchEvidenceTab(this, '${tab}')">${tab}</button>`).join('')}
                        </div>`;
                }

                // Show evidence content
                const scriptVal = tech.scriptSrc || tech.scripts;
                if (scriptVal) {
                    const srcValue = typeof scriptVal === 'string' ? scriptVal : (Array.isArray(scriptVal) ? scriptVal.join('\\n') : JSON.stringify(scriptVal));
                    html += `<div class="evidence-code-block" data-evidence="scriptSrc">${esc(srcValue)}</div>`;
                }
                if (tech.pattern) {
                    const patternValue = typeof tech.pattern === 'string' ? tech.pattern : JSON.stringify(tech.pattern);
                    html += `<div class="evidence-code-block" data-evidence="pattern" style="${scriptVal ? 'display:none;' : ''}">${esc(patternValue)}</div>`;
                }
                if (tech.html) {
                    const htmlValue = typeof tech.html === 'string' ? tech.html : JSON.stringify(tech.html);
                    html += `<div class="evidence-code-block" data-evidence="html" style="display:none;">${esc(htmlValue)}</div>`;
                }
                if (tech.url) {
                    const urlValue = typeof tech.url === 'string' ? tech.url : JSON.stringify(tech.url);
                    html += `<div class="evidence-code-block" data-evidence="url" style="display:none;">${esc(urlValue)}</div>`;
                }
                if (tech.certIssuer) {
                    const certValue = typeof tech.certIssuer === 'string' ? tech.certIssuer : JSON.stringify(tech.certIssuer);
                    html += `<div class="evidence-code-block" data-evidence="certIssuer" style="display:none;">${esc(certValue)}</div>`;
                }
            }

            // Match section
            if (tech.match) {
                const matchValue = typeof tech.match === 'string' ? tech.match : JSON.stringify(tech.match);
                html += `<div class="evidence-match-label">MATCH:</div>
                            <div class="evidence-match-value">${esc(matchValue)}</div>`;
            }

            html += `</div>`;
        }

        // Additional metadata
        let metaHtml = '';
        if (tech.cpe) {
            metaHtml += `<div class="evidence-meta-row">
                    <span class="evidence-meta-label">CPE</span>
                    <span class="evidence-meta-value">${esc(tech.cpe)}</span>
                </div>`;
        }
        if (tech.implies && tech.implies.length > 0) {
            metaHtml += `<div class="evidence-meta-row">
                    <span class="evidence-meta-label">Implies</span>
                    <span class="evidence-meta-value">${esc(tech.implies.join(', '))}</span>
                </div>`;
        }
        if (tech.requires && tech.requires.length > 0) {
            metaHtml += `<div class="evidence-meta-row">
                    <span class="evidence-meta-label">Requires</span>
                    <span class="evidence-meta-value">${esc(tech.requires.join(', '))}</span>
                </div>`;
        }

        if (metaHtml) {
            html += `<div class="evidence-section">
                    <div class="evidence-section-title">Additional Info</div>
                    ${metaHtml}
                </div>`;
        }

        if (!html) {
            html = '<div class="loading-text">No detailed evidence available for this technology</div>';
        }

        bodyEl.innerHTML = html;
        modal.classList.add('active');
    };

    // Note: closeEvidenceModal is defined globally in a separate script block above

    // Switch between evidence tabs
    window.switchEvidenceTab = function (btn, tabName) {
        // Update active tab button
        const tabs = btn.parentElement.querySelectorAll('.evidence-tab');
        tabs.forEach(t => t.classList.remove('active'));
        btn.classList.add('active');

        // Show/hide evidence code blocks
        const section = btn.closest('.evidence-section');
        const blocks = section.querySelectorAll('.evidence-code-block');
        blocks.forEach(block => {
            if (block.dataset.evidence === tabName) {
                block.style.display = 'block';
            } else {
                block.style.display = 'none';
            }
        });
    };

    // Card click handlers
    document.querySelectorAll('.report-card').forEach(card => {
        card.addEventListener('click', () => {
            const cat = CATEGORIES.find(c => c.api === card.dataset.category);
            if (cat) {
                openCategory(cat.api, cat.name);
            } else {
                // Fallback for direct category names
                openCategory(card.dataset.category, card.querySelector('.report-card-title').textContent);
            }
        });
    });

    // Initialize
    init();
})();
