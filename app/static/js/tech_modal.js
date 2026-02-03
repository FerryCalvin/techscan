// tech_modal.js — lightweight modal controller aligned with stats modal behaviour
(function () {
  'use strict';

  if (typeof document === 'undefined') {
    return;
  }

  var modal = document.getElementById('tech-modal');
  if (!modal) {
    return;
  }

  var overlay = document.getElementById('tech-modal-overlay');
  var nameEl = document.getElementById('tech-modal-name');
  var subEl = document.getElementById('tech-modal-sub');
  var summaryEl = document.getElementById('tech-modal-summary-inner');
  var evidenceEl = document.getElementById('tech-evidence-list');
  var sitesEl = document.getElementById('tech-modal-sites-list');
  var pagerEl = document.getElementById('tech-modal-sites-pager');
  var searchInput = document.getElementById('tech-modal-search');
  var exportBtn = document.getElementById('tech-modal-export');
  var closeBtn = document.getElementById('tech-modal-close');
  var viewBtn = document.getElementById('tech-modal-view-websites');
  var iconEl = document.getElementById('tech-modal-icon');
  var footerLeft = document.getElementById('tech-modal-footer-left');
  var evidenceModal = document.getElementById('evidence-modal');
  var evidenceOverlay = document.getElementById('evidence-modal-overlay');
  var evidenceCloseBtn = document.getElementById('evidence-modal-close');
  var evidenceTrigger = document.getElementById('tech-modal-open-evidence');
  var evidenceNameEl = document.getElementById('evidence-modal-name');
  var evidenceMetaEl = document.getElementById('evidence-modal-meta');

  var state = {
    currentTech: null,
    preload: null,
    rawDomains: [],
    filteredDomains: [],
    page: 0,
    perPage: 20,
    footer: {
      domainCount: null,
      firstSeen: null,
      lastSeen: null,
      lastUpdated: null
    },
    metaSummary: null,
    metaDetail: null
  };

  var customEvidencePayload = null;

  function applyCustomEvidence() {
    if (!evidenceEl) {
      return;
    }
    var existing = evidenceEl.querySelector('.tech-custom-evidence');
    if (existing && existing.parentNode === evidenceEl) {
      existing.remove();
    }
    if (!customEvidencePayload || !customEvidencePayload.html) {
      return;
    }
    var placeholder = evidenceEl.querySelector('.small-note');
    if (placeholder && placeholder.parentNode === evidenceEl) {
      placeholder.remove();
    }
    var wrapper = document.createElement('section');
    wrapper.className = 'tech-custom-evidence';

    if (customEvidencePayload.title) {
      var heading = document.createElement('h4');
      heading.className = 'tech-custom-evidence-title';
      heading.textContent = customEvidencePayload.title;
      wrapper.appendChild(heading);
    }

    var body = document.createElement('div');
    body.className = 'tech-custom-evidence-body';
    body.innerHTML = customEvidencePayload.html;
    wrapper.appendChild(body);

    if (customEvidencePayload.raw) {
      var details = document.createElement('details');
      details.className = 'tech-custom-evidence-raw';
      var summary = document.createElement('summary');
      summary.textContent = 'Show raw evidence JSON';
      details.appendChild(summary);
      var pre = document.createElement('pre');
      try {
        pre.textContent = typeof customEvidencePayload.raw === 'string'
          ? customEvidencePayload.raw
          : JSON.stringify(customEvidencePayload.raw, null, 2);
      } catch (err) {
        pre.textContent = 'Unable to format evidence payload.';
      }
      details.appendChild(pre);
      wrapper.appendChild(details);
    }

    evidenceEl.appendChild(wrapper);

    if (typeof customEvidencePayload.onRender === 'function') {
      try {
        customEvidencePayload.onRender(body);
      } catch (err) {
        console.warn('[tech_modal] custom evidence render failed', err);
      }
    }
  }

  function setCustomEvidence(payload) {
    if (!payload) {
      customEvidencePayload = null;
    } else {
      customEvidencePayload = {
        html: payload.html || '',
        title: payload.title || '',
        raw: payload.raw || null,
        onRender: typeof payload.onRender === 'function' ? payload.onRender : null
      };
    }
    applyCustomEvidence();
  }

  var ESC_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };

  var previouslyFocused = null;
  var evidencePreviouslyFocused = null;

  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return '';
    }
    return String(value).replace(/[&<>"']/g, function (ch) {
      return ESC_MAP[ch] || ch;
    });
  }

  function normaliseCategories(categories, category) {
    if (Array.isArray(categories) && categories.length) {
      return categories;
    }
    if (typeof categories === 'string' && categories.trim()) {
      return categories.split(',').map(function (item) { return item.trim(); }).filter(Boolean);
    }
    if (category && typeof category === 'string') {
      return [category];
    }
    return [];
  }

  function mergePreload(primary, fallback) {
    var merged = {};
    if (fallback && typeof fallback === 'object') {
      for (var key in fallback) {
        if (Object.prototype.hasOwnProperty.call(fallback, key)) {
          var value = fallback[key];
          if (value !== undefined && value !== null) {
            merged[key] = value;
          }
        }
      }
    }
    if (primary && typeof primary === 'object') {
      for (var pKey in primary) {
        if (Object.prototype.hasOwnProperty.call(primary, pKey)) {
          var pVal = primary[pKey];
          if (pVal !== undefined && pVal !== null) {
            merged[pKey] = pVal;
          }
        }
      }
    }
    return merged;
  }

  function normalisePreload(preload, fallbackName) {
    if (!preload || typeof preload !== 'object') {
      return { name: fallbackName || '' };
    }
    var categories = normaliseCategories(preload.categories, preload.category);
    return {
      name: preload.name || preload.tech || fallbackName || '',
      categories: categories,
      version: preload.version || preload.detected_version || '',
      confidence: preload.avg_confidence !== undefined ? preload.avg_confidence : preload.confidence,
      count: preload.count,
      domains: Array.isArray(preload.domains) ? preload.domains.slice() : null,
      iconUrl: preload.icon_url || preload.iconUrl || '',
      iconSlug: preload.icon_slug || preload.iconSlug || preload.slug || '',
      iconFallback: preload.iconFallback || ''
    };
  }

  function formatTimestamp(raw) {
    if (!raw && raw !== 0) {
      return '';
    }
    var num = Number(raw);
    if (!isNaN(num)) {
      if (num > 1e12) {
        num = num / 1000;
      }
      var date = new Date(num * 1000);
      if (!isNaN(date.getTime())) {
        return date.toLocaleString();
      }
    }
    return String(raw);
  }

  function openModal() {
    previouslyFocused = document.activeElement;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    if (overlay) {
      overlay.classList.add('active');
    }
    if (closeBtn && typeof closeBtn.focus === 'function') {
      setTimeout(function () { try { closeBtn.focus(); } catch (err) { } }, 0);
    }
    document.addEventListener('keydown', onKeyDown, true);
  }

  function closeModal() {
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    if (overlay) {
      overlay.classList.remove('active');
    }
    document.removeEventListener('keydown', onKeyDown, true);
    setCustomEvidence(null);
    if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
      setTimeout(function () { try { previouslyFocused.focus(); } catch (err) { } }, 40);
    }
    closeEvidenceModal();
  }

  function openEvidenceModal() {
    if (!evidenceModal || !state.currentTech) {
      return;
    }
    updateEvidenceHeader();
    evidencePreviouslyFocused = document.activeElement;
    evidenceModal.classList.add('active');
    evidenceModal.setAttribute('aria-hidden', 'false');
    if (evidenceOverlay) {
      evidenceOverlay.classList.add('active');
    }
    if (evidenceCloseBtn && typeof evidenceCloseBtn.focus === 'function') {
      setTimeout(function () { try { evidenceCloseBtn.focus(); } catch (err) { } }, 0);
    }
    document.addEventListener('keydown', onEvidenceKeyDown, true);
  }

  function closeEvidenceModal() {
    if (!evidenceModal) {
      return;
    }
    evidenceModal.classList.remove('active');
    evidenceModal.setAttribute('aria-hidden', 'true');
    if (evidenceOverlay) {
      evidenceOverlay.classList.remove('active');
    }
    document.removeEventListener('keydown', onEvidenceKeyDown, true);
    if (evidencePreviouslyFocused && typeof evidencePreviouslyFocused.focus === 'function') {
      setTimeout(function () { try { evidencePreviouslyFocused.focus(); } catch (err) { } }, 40);
    }
  }

  function onKeyDown(event) {
    var e = event || window.event;
    if (!modal.classList.contains('active')) {
      return;
    }
    if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) {
      try { e.preventDefault(); } catch (err) { }
      closeModal();
    }
  }

  function onEvidenceKeyDown(event) {
    var e = event || window.event;
    if (!evidenceModal || !evidenceModal.classList.contains('active')) {
      return;
    }
    if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) {
      try { e.preventDefault(); } catch (err) { }
      closeEvidenceModal();
    }
  }

  function setSummaryLoading() {
    if (summaryEl) {
      summaryEl.innerHTML = '<div class="small-note">Loading metadata…</div>';
    }
  }

  function setEvidenceLoading() {
    if (evidenceEl) {
      evidenceEl.innerHTML = '<div class="small-note">Loading evidence…</div>';
      applyCustomEvidence();
    }
  }

  function setSitesLoading() {
    if (sitesEl) {
      sitesEl.innerHTML = '<div class="small-note">Loading domains…</div>';
    }
    if (pagerEl) {
      pagerEl.innerHTML = '';
    }
  }

  function refreshFooter() {
    if (footerLeft) {
      var parts = [];
      if (state.footer.domainCount !== null) {
        parts.push(state.footer.domainCount + ' domains');
      }
      if (state.footer.lastSeen) {
        parts.push('Last seen ' + formatTimestamp(state.footer.lastSeen));
      } else if (state.footer.firstSeen) {
        parts.push('First seen ' + formatTimestamp(state.footer.firstSeen));
      }
      if (state.footer.lastUpdated) {
        parts.push('Updated ' + state.footer.lastUpdated);
      }
      footerLeft.textContent = parts.join(' • ');
    }
    updateEvidenceHeader();
  }

  function updateEvidenceHeader() {
    if (evidenceNameEl) {
      evidenceNameEl.textContent = state.currentTech || 'Technology';
    }
    if (!evidenceMetaEl) {
      return;
    }
    var chips = [];
    if (state.footer.domainCount !== null) {
      chips.push(state.footer.domainCount + ' domains');
    }
    if (state.footer.lastSeen) {
      chips.push('Last seen ' + formatTimestamp(state.footer.lastSeen));
    } else if (state.footer.firstSeen) {
      chips.push('First seen ' + formatTimestamp(state.footer.firstSeen));
    }
    if (state.footer.lastUpdated) {
      chips.push('Updated ' + state.footer.lastUpdated);
    }
    evidenceMetaEl.textContent = chips.join(' • ');
  }

  function renderSummary(meta, preload) {
    if (!summaryEl) {
      return;
    }
    var detected = (meta && meta.detected_version) || (preload && preload.version) || '—';
    var confidence = meta && meta.confidence;
    if (confidence === undefined || confidence === null) {
      confidence = preload && preload.confidence !== undefined ? preload.confidence : null;
    }
    if (typeof confidence === 'number') {
      confidence = confidence.toFixed(2);
    }
    var totalSites = 0;
    if (meta && meta.counts && typeof meta.counts.total_sites === 'number') {
      totalSites = meta.counts.total_sites;
    } else if (preload && typeof preload.count === 'number') {
      totalSites = preload.count;
    } else if (preload && preload.domains) {
      totalSites = preload.domains.length;
    } else if (state.rawDomains && state.rawDomains.length) {
      totalSites = state.rawDomains.length;
    }
    summaryEl.innerHTML = '' +
      '<div class="tech-meta-row"><strong>Detected:</strong> ' + escapeHtml(detected || '—') + '</div>' +
      '<div class="tech-meta-row"><strong>Confidence:</strong> ' + escapeHtml(confidence !== null && confidence !== undefined ? confidence : '—') + '</div>' +
      '<div class="tech-meta-row"><strong>Total sites:</strong> ' + escapeHtml(totalSites) + '</div>';
  }

  function renderEvidence(meta) {
    if (!evidenceEl) {
      return;
    }
    var sections = [];
    if (meta && Array.isArray(meta.top_versions) && meta.top_versions.length) {
      sections.push('<div class="small-note">Top versions:</div>');
      sections.push('<ul class="evidence-list">' + meta.top_versions.slice(0, 5).map(function (item) {
        var version = item && item.version ? item.version : 'Unknown';
        var count = item && item.count !== undefined ? item.count : '';
        return '<li>' + escapeHtml(version) + (count !== '' ? ' — ' + escapeHtml(count) + ' sites' : '') + '</li>';
      }).join('') + '</ul>');
    }
    if (meta && Array.isArray(meta.sample_sites) && meta.sample_sites.length) {
      sections.push('<div class="small-note">Sample domains:</div>');
      sections.push('<ul class="evidence-list">' + meta.sample_sites.slice(0, 5).map(function (site) {
        var domain = site && site.domain ? site.domain : '';
        if (!domain) {
          return '';
        }
        return '<li><a href="/domain/' + encodeURIComponent(domain) + '">' + escapeHtml(domain) + '</a></li>';
      }).filter(Boolean).join('') + '</ul>');
    }
    if (!sections.length) {
      evidenceEl.innerHTML = '<div class="small-note">Evidence not available in aggregate view.</div>';
      applyCustomEvidence();
      return;
    }
    evidenceEl.innerHTML = sections.join('');
    applyCustomEvidence();
  }

  function renderTrendInfo(detail) {
    var section = document.getElementById('tech-trend');
    if (!section) {
      return;
    }
    var canvas = document.getElementById('modalTrend');
    if (canvas) {
      canvas.style.display = 'none';
    }
    var noteId = 'tech-trend-note';
    var existing = document.getElementById(noteId);
    if (existing && existing.parentNode === section) {
      section.removeChild(existing);
    }
    var history = [];
    if (detail && Array.isArray(detail.history)) {
      history = detail.history;
    } else if (detail && Array.isArray(detail.trend)) {
      history = detail.trend;
    }
    var note = document.createElement('div');
    note.id = noteId;
    note.className = 'small-note';
    if (!history.length) {
      note.textContent = 'Trend data unavailable.';
      section.appendChild(note);
      return;
    }
    var latest = history[history.length - 1];
    var latestValue = latest && (latest.v !== undefined ? latest.v : (latest.count !== undefined ? latest.count : latest.value));
    note.textContent = 'Trend records: ' + history.length + (latestValue !== undefined ? ' • Latest value: ' + latestValue : '');
    section.appendChild(note);
  }

  function applyDomainsFilter(query) {
    var q = (query || '').trim().toLowerCase();
    var source = state.rawDomains || [];
    if (!q) {
      state.filteredDomains = source.slice();
    } else {
      state.filteredDomains = source.filter(function (domain) {
        return domain && domain.toLowerCase().indexOf(q) !== -1;
      });
    }
    state.page = 0;
    renderDomains();
  }

  function renderDomains() {
    if (!sitesEl) {
      return;
    }
    var list = state.filteredDomains || [];
    if (!list.length) {
      sitesEl.innerHTML = '<div class="small-note">No domains found.</div>';
      if (pagerEl) {
        pagerEl.innerHTML = '';
      }
      return;
    }
    var start = state.page * state.perPage;
    if (start >= list.length) {
      state.page = 0;
      start = 0;
    }
    var slice = list.slice(start, start + state.perPage);
    sitesEl.innerHTML = slice.map(function (domain) {
      var safe = escapeHtml(domain);
      return '<div class="site-card"><a class="site-link" href="https://' + safe + '" target="_blank" rel="noopener">' + safe + '</a></div>';
    }).join('');
    if (pagerEl) {
      var totalPages = Math.max(1, Math.ceil(list.length / state.perPage));
      pagerEl.innerHTML = '' +
        '<button type="button" class="btn btn-small tech-pager-prev"' + (state.page === 0 ? ' disabled' : '') + '>Prev</button>' +
        '<span class="pager-info">Page ' + (state.page + 1) + ' / ' + totalPages + '</span>' +
        '<button type="button" class="btn btn-small tech-pager-next"' + (state.page >= totalPages - 1 ? ' disabled' : '') + '>Next</button>';
    }
  }

  function changePage(delta) {
    var list = state.filteredDomains || [];
    if (!list.length) {
      return;
    }
    var totalPages = Math.max(1, Math.ceil(list.length / state.perPage));
    var nextPage = state.page + delta;
    if (nextPage < 0 || nextPage >= totalPages) {
      return;
    }
    state.page = nextPage;
    renderDomains();
  }

  function fetchJson(url) {
    return fetch(url, { cache: 'no-store' }).then(function (res) {
      if (!res.ok) {
        throw new Error('HTTP ' + res.status);
      }
      return res.json();
    });
  }

  function loadMeta(name) {
    setSummaryLoading();
    setEvidenceLoading();
    var summaryPromise = fetchJson('/api/tech/' + encodeURIComponent(name)).catch(function (err) {
      console.warn('tech modal summary fetch failed', err);
      return null;
    });
    var detailPromise = fetchJson('/api/techs/' + encodeURIComponent(name)).catch(function (err) {
      console.warn('tech modal detail fetch failed', err);
      return null;
    });
    return Promise.all([summaryPromise, detailPromise]).then(function (results) {
      var summary = results[0] || null;
      var detail = results[1] || null;
      state.metaSummary = summary || null;
      state.metaDetail = detail || null;
      if (summary && summary.counts && typeof summary.counts.total_sites === 'number') {
        state.footer.domainCount = summary.counts.total_sites;
      }
      if (detail && typeof detail.count === 'number') {
        state.footer.domainCount = detail.count;
      }
      if (detail && detail.first_seen) {
        state.footer.firstSeen = detail.first_seen;
      }
      if (detail && detail.last_seen) {
        state.footer.lastSeen = detail.last_seen;
      }
      if (summary && summary.last_updated) {
        state.footer.lastUpdated = summary.last_updated;
      }
      refreshFooter();
      renderSummary(summary || detail || {}, state.preload);
      renderEvidence(summary || detail || {});
      renderTrendInfo(detail || summary || null);
      updateEvidenceHeader();
    }).catch(function (err) {
      console.warn('tech modal meta fetch failed', err);
      if (summaryEl) {
        summaryEl.innerHTML = '<div class="small-note">Metadata unavailable.</div>';
      }
      if (evidenceEl) {
        evidenceEl.innerHTML = '<div class="small-note">Evidence unavailable.</div>';
      }
      renderTrendInfo(null);
    });
  }

  function loadDomains(name) {
    setSitesLoading();
    return fetchJson('/api/tech/' + encodeURIComponent(name) + '/domains?t=' + Date.now()).then(function (data) {
      var domains = data && Array.isArray(data.domains) ? data.domains : [];
      state.rawDomains = domains.slice();
      if (data && typeof data.count === 'number') {
        state.footer.domainCount = data.count;
      } else {
        state.footer.domainCount = domains.length;
      }
      refreshFooter();
      applyDomainsFilter(searchInput ? searchInput.value : '');
    }).catch(function (err) {
      console.warn('tech modal domains fetch failed', err);
      state.rawDomains = [];
      state.filteredDomains = [];
      if (sitesEl) {
        sitesEl.innerHTML = '<div class="small-note">Failed to load domains.</div>';
      }
      if (pagerEl) {
        pagerEl.innerHTML = '';
      }
    });
  }

  function derivePreloadFromDashboard(name) {
    var techs = window._latestTechs || [];
    var lower = name.toLowerCase();
    for (var i = 0; i < techs.length; i++) {
      var item = techs[i];
      if (item && (item.name || '').toLowerCase() === lower) {
        return item;
      }
    }
    return null;
  }

  function updateSubHeading(preload) {
    if (!subEl) {
      return;
    }
    var categories = preload && preload.categories ? preload.categories : [];
    if (!categories.length && preload && preload.category) {
      categories = normaliseCategories(null, preload.category);
    }
    if (categories.length) {
      subEl.textContent = 'Category: ' + categories.join(', ');
      return;
    }
    subEl.textContent = '';
  }

  function resetIcon() {
    if (!iconEl) {
      return;
    }
    iconEl.src = '/static/assets/images/placeholder-tech.svg';
    iconEl.alt = '';
  }

  function iconColorFor(name) {
    if (!name) return '#ccc';
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
    const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
    return '#' + '00000'.substring(0, 6 - c.length) + c;
  }

  function openForName(name, preload) {
    if (!name) {
      return;
    }
    var actualName = String(name).trim();
    state.currentTech = actualName;
    state.preload = mergePreload(
      normalisePreload(preload, actualName),
      normalisePreload(derivePreloadFromDashboard(actualName), actualName)
    );
    state.rawDomains = [];
    state.filteredDomains = [];
    state.page = 0;
    state.footer = {
      domainCount: null,
      firstSeen: null,
      lastSeen: null,
      lastUpdated: null
    };
    setCustomEvidence(null);
    if (nameEl) {
      nameEl.textContent = actualName;
    }
    updateSubHeading(state.preload);
    resetIcon();

    // Tech Icon Handling
    if (iconEl) {
      iconEl.style.display = 'none'; // Hidden initally

      // Clear previous fallback
      var iconContainer = iconEl.parentElement;
      if (iconContainer) {
        var oldFallback = iconContainer.querySelector('.tech-icon-fallback');
        if (oldFallback) oldFallback.remove();
      }

      // 1. Determine Icon Key
      var techName = actualName;
      var iconKey = techName.toLowerCase().replace(/[^a-z0-9+#]/g, '');
      var iconMap = {
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
      if (iconMap[techName.toLowerCase()]) {
        iconKey = iconMap[techName.toLowerCase()];
      } else if (iconMap[iconKey]) {
        iconKey = iconMap[iconKey];
      }

      var localPath = '/static/icons/tech/' + encodeURIComponent(iconKey) + '.svg';

      iconEl.src = localPath;

      // 2. Load handlers
      iconEl.onload = function () {
        this.style.display = 'block';
      };
      iconEl.onerror = function () {
        this.style.display = 'none';
        if (iconContainer) {
          var letter = techName.charAt(0).toUpperCase();
          var color = iconColorFor(techName);
          var fallback = document.createElement('div');
          fallback.className = 'tech-icon-fallback';
          var s = fallback.style;
          s.backgroundColor = color;
          s.display = 'flex';
          s.alignItems = 'center';
          s.justifyContent = 'center';
          s.color = 'white';
          s.fontWeight = 'bold';
          s.fontSize = '24px';
          s.borderRadius = '8px';
          s.width = '48px';
          s.height = '48px';
          fallback.textContent = letter;
          iconContainer.insertBefore(fallback, iconEl);
        }
      };

      if (state.preload.category) {
        iconEl.alt = state.preload.category + ' icon';
      } else {
        iconEl.alt = state.preload.name || '';
      }
    }
    refreshFooter();
    if (searchInput) {
      searchInput.value = '';
    }
    setSummaryLoading();
    setEvidenceLoading();
    setSitesLoading();
    openModal();
    Promise.all([
      loadMeta(actualName),
      loadDomains(actualName)
    ]).catch(function (err) {
      console.warn('tech modal load failed', err);
    });
  }

  function resolveCardTechName(card) {
    if (!card) {
      return '';
    }
    var dataName = card.getAttribute('data-tech') || card.getAttribute('data-name');
    if (dataName) {
      dataName = dataName.replace(/&#10;/g, '\n').replace(/&(amp|lt|gt|quot|#39);/g, function (entity) {
        switch (entity) {
          case '&amp;': return '&';
          case '&lt;': return '<';
          case '&gt;': return '>';
          case '&quot;': return '"';
          case '&#39;': return "'";
          default: return entity;
        }
      });
    }
    var title = card.getAttribute('title');
    var extracted = '';
    if (dataName) {
      extracted = dataName;
    } else {
      var header = card.querySelector && card.querySelector('h5');
      if (header) {
        extracted = header.textContent || '';
      } else if (title) {
        extracted = title.split('\n')[0];
      } else {
        extracted = (card.textContent || '').split('\n')[0];
      }
    }
    extracted = extracted.replace(/\s+v[0-9].*$/i, '').trim();
    return extracted;
  }

  function handleCardClick(event) {
    var target = event.target || event.srcElement;
    if (!target) {
      return;
    }
    if (target.closest && target.closest('.evidence-btn')) {
      return;
    }
    var card = target.closest ? target.closest('.tech-card') : null;
    if (!card) {
      return;
    }
    try { event.preventDefault(); } catch (err) { }
    var extracted = resolveCardTechName(card);
    if (!extracted) {
      return;
    }
    openForName(extracted);
  }

  function handleCardKeydown(event) {
    var target = event.target || event.srcElement;
    if (!target || !(target.classList && target.classList.contains('tech-card'))) {
      return;
    }
    var key = event.key || event.keyCode;
    var isEnter = key === 'Enter' || key === 'enter' || key === 13;
    var isSpace = key === ' ' || key === 'Spacebar' || key === 'spacebar' || key === 32;
    if (!isEnter && !isSpace) {
      return;
    }
    try { event.preventDefault(); } catch (err) { }
    var extracted = resolveCardTechName(target);
    if (!extracted) {
      return;
    }
    openForName(extracted);
  }

  function attachCardListeners() {
    if (typeof window !== 'undefined' && window.__DISABLE_GLOBAL_TECH_CARD_MODAL) {
      return;
    }
    document.addEventListener('click', handleCardClick, false);
    document.addEventListener('keydown', handleCardKeydown, false);
  }

  function attachPagerListener() {
    if (!pagerEl) {
      return;
    }
    pagerEl.addEventListener('click', function (event) {
      var target = event.target || event.srcElement;
      if (!target || target.disabled) {
        return;
      }
      if (target.classList.contains('tech-pager-prev')) {
        changePage(-1);
      } else if (target.classList.contains('tech-pager-next')) {
        changePage(1);
      }
    });
  }

  function attachSearchListener() {
    if (!searchInput) {
      return;
    }
    searchInput.addEventListener('input', function () {
      applyDomainsFilter(this.value);
    });
  }

  function attachCloseHandlers() {
    if (overlay) {
      overlay.addEventListener('click', function (event) {
        if (event.target === overlay || (event.target && event.target.getAttribute && event.target.getAttribute('data-close') === 'true')) {
          closeModal();
        }
      });
    }
    if (closeBtn) {
      closeBtn.addEventListener('click', function (e) {
        try { e.preventDefault(); } catch (err) { }
        closeModal();
      });
    }
    if (evidenceOverlay) {
      evidenceOverlay.addEventListener('click', function (event) {
        if (event.target === evidenceOverlay || (event.target && event.target.getAttribute && event.target.getAttribute('data-close') === 'true')) {
          closeEvidenceModal();
        }
      });
    }
    if (evidenceCloseBtn) {
      evidenceCloseBtn.addEventListener('click', function (e) {
        try { e.preventDefault(); } catch (err) { }
        closeEvidenceModal();
      });
    }
  }

  function attachExportHandler() {
    if (!exportBtn) {
      return;
    }
    exportBtn.addEventListener('click', function (e) {
      try { e.preventDefault(); } catch (err) { }
      if (!state.currentTech) {
        return;
      }
      fetch('/api/tech/' + encodeURIComponent(state.currentTech) + '/sites.csv?limit=2000').then(function (res) {
        if (!res.ok) {
          throw new Error('HTTP ' + res.status);
        }
        return res.blob();
      }).then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = state.currentTech + '_sites.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }).catch(function (err) {
        alert('Export failed: ' + (err && err.message ? err.message : err));
      });
    });
  }

  function attachViewHandler() {
    if (!viewBtn) {
      return;
    }
    viewBtn.addEventListener('click', function (e) {
      try { e.preventDefault(); } catch (err) { }
      if (!state.currentTech) {
        return;
      }
      window.location.href = '/websites?tech=' + encodeURIComponent(state.currentTech);
    });
  }

  attachCardListeners();
  attachPagerListener();
  attachSearchListener();
  attachCloseHandlers();
  attachExportHandler();
  attachViewHandler();

  if (evidenceTrigger) {
    evidenceTrigger.addEventListener('click', function (e) {
      try { e.preventDefault(); } catch (err) { }
      openEvidenceModal();
    });
  }

  window.techModalSetCustomEvidence = setCustomEvidence;
  window.showTechModal = function (name, preload) {
    openForName(name, preload);
  };
  window._showTechModalRaw = openForName;
  window.closeModal = closeModal;
  window.closeTechModal = closeModal;
  window.closeEvidenceModal = closeEvidenceModal;
  window.openTechModal = function (tech) {
    if (!tech) {
      return;
    }
    if (typeof tech === 'string') {
      openForName(tech);
      return;
    }
    var name = tech.tech || tech.name || tech.slug || tech.tech_key || '';
    openForName(name, tech);
  };
  window.openEvidenceModal = openEvidenceModal;

  if (console && console.debug) {
    console.debug('[tech_modal] ready (stats-aligned)');
  }

})();
