  const singleForm = document.getElementById('single-scan-form');
  const resultsBox = document.getElementById('results');
  const categoryGroups = document.getElementById('category-groups');
  const rawPre = document.getElementById('raw-json');
  const statusLine = document.getElementById('status-line');
  const metaLine = document.getElementById('meta-line');
  const errorBox = document.getElementById('error-box');
  const phaseBreakdownEl = document.getElementById('phase-breakdown');
  const scanBtn = document.getElementById('scan-btn');
  const scanBtnOriginalText = scanBtn && scanBtn.textContent ? scanBtn.textContent.trim() || 'Scan' : 'Scan';

  let singleController = null;
  let singleRequestToken = null;
  let progressBarEl = null;
  let progressLabelEl = null;
  let progressEtaEl = null;
  let progressState = null;
  let progressResetTimer = null;

  const dashModal = document.getElementById('dash-tech-modal');
  const dashModalOverlay = document.getElementById('dash-tech-overlay');
  const dashModalClose = document.getElementById('dash-tech-close');
  const dashModalPanel = dashModal ? dashModal.querySelector('.dash-modal-panel') : null;
  const dashTechName = document.getElementById('dash-tech-name');
  const dashTechSites = document.getElementById('dash-tech-sites');
  const dashTechSitesFilter = document.getElementById('dash-tech-sites-filter');
  const dashTechSitesMeta = document.getElementById('dash-tech-sites-meta');
  const dashTechEvidence = document.getElementById('dash-tech-evidence');
  const dashEvidenceSource = document.getElementById('dash-evidence-source');
  let dashModalEscHandlerAttached = false;
  let dashModalLastFocus = null;
  let dashHighlightEvidenceNext = false;
  const dashDomainCache = new Map();
  const dashDomainState = {
    currentKey: '',
    domains: [],
    filtered: [],
    total: 0
  };
  const dashEvidenceState = {
    techKey: '',
    currentDomain: '',
    pendingDomain: '',
    localFallback: null,
    lastFetchToken: 0
  };

  function resetDashboardEvidenceState(techLabel, fallbackTech) {
    dashEvidenceState.techKey = (techLabel || '').trim();
    dashEvidenceState.currentDomain = '';
    dashEvidenceState.pendingDomain = '';
    dashEvidenceState.localFallback = fallbackTech || null;
    dashEvidenceState.lastFetchToken++;
    setDashboardEvidenceSource('Showing latest scan evidence while stored proof loads…', 'muted');
    if (dashTechEvidence) {
      dashTechEvidence.innerHTML = renderDashboardEvidenceEntries(fallbackTech);
    }
  }

  function setDashboardEvidenceSource(text, variant) {
    if (!dashEvidenceSource) {
      return;
    }
    dashEvidenceSource.textContent = text || '';
    dashEvidenceSource.classList.toggle('is-error', variant === 'error');
    dashEvidenceSource.classList.toggle('is-muted', variant === 'muted');
  }

  function setDashboardEvidenceLoading(message) {
    if (!dashTechEvidence) {
      return;
    }
    const label = message || 'Loading evidence…';
    dashTechEvidence.innerHTML = `<li class="dash-evidence-loading">${escapeHtml(label)}</li>`;
  }

  function setDashboardEvidenceEntries(entries) {
    if (!dashTechEvidence) {
      return;
    }
    dashTechEvidence.innerHTML = renderDashboardEvidenceList(entries);
  }

  function setDashboardEvidenceFallback(message, variant) {
    const note = message || 'Showing evidence from the latest scan payload.';
    setDashboardEvidenceSource(note, variant || 'muted');
    if (dashEvidenceState.localFallback) {
      dashTechEvidence.innerHTML = renderDashboardEvidenceEntries(dashEvidenceState.localFallback);
    } else if (dashTechEvidence) {
      const className = variant === 'error' ? 'dash-evidence-error' : 'dash-evidence-empty';
      dashTechEvidence.innerHTML = `<li class="${className}">${escapeHtml(note)}</li>`;
    }
    dashEvidenceState.currentDomain = '';
    dashEvidenceState.pendingDomain = '';
    updateDashboardEvidenceActiveStyles();
  }

  function formatDashboardConfidence(value) {
    if (value === null || value === undefined) {
      return '';
    }
    const num = Number(value);
    if (Number.isFinite(num)) {
      return `${Math.round(num)}%`;
    }
    return String(value);
  }

  function extractDashboardCategories(tech) {
    if (!tech || typeof tech !== 'object') {
      return [];
    }
    const normalized = normalizeCategories(tech.categories);
    if (normalized.length) {
      return normalized;
    }
    if (typeof tech.category === 'string' && tech.category.trim()) {
      return [tech.category.trim()];
    }
    return [];
  }

  function formatDateTime(value) {
    if (value === null || value === undefined) {
      return '';
    }
    let dateObj = null;
    if (value instanceof Date) {
      dateObj = value;
    } else if (typeof value === 'number') {
      const ms = value > 1e12 ? value : value * 1000;
      dateObj = new Date(ms);
    } else if (typeof value === 'string') {
      const trimmed = value.trim();
      if (trimmed) {
        const parsed = Date.parse(trimmed);
        if (!Number.isNaN(parsed)) {
          dateObj = new Date(parsed);
        }
      }
    } else if (value && typeof value === 'object') {
      if (typeof value.timestamp === 'function') {
        try {
          dateObj = new Date(value.timestamp() * 1000);
        } catch (_) {
          dateObj = null;
        }
      } else if (Number.isFinite(value.seconds)) {
        dateObj = new Date(value.seconds * 1000);
      }
    }
    if (!dateObj || Number.isNaN(dateObj.getTime())) {
      return '';
    }
    return dateObj.toLocaleString(undefined, { hour12: false });
  }

  function formatDetectionWindow(tech) {
    if (!tech) {
      return 'Latest scan';
    }
    const last = formatDateTime(tech.last_seen || tech.last_detected);
    const first = formatDateTime(tech.first_seen || tech.first_detected);
    if (last && first && last !== first) {
      return `${first}  ${last}`;
    }
    if (last || first) {
      return last || first;
    }
    const scan = window._latestScan || {};
    return formatDateTime(scan.finished_at || scan.completed_at || scan.timestamp) || 'Latest scan';
  }

  function buildDashboardHighlights(tech) {
    const highlights = [];
    const scan = window._latestScan || {};
    const finishedLabel = formatDateTime(scan.finished_at || scan.completed_at || scan.timestamp);
    if (finishedLabel) {
      highlights.push(`Scan completed ${finishedLabel}`);
    }
    const durationMs = computeActualDurationMs(scan);
    if (Number.isFinite(durationMs)) {
      highlights.push(`Duration ${formatMs(durationMs)}`);
    }
    const payloadLabel = formatBytes(scan.payload_bytes);
    if (payloadLabel) {
      highlights.push(`Payload ${payloadLabel}`);
    }
    if (scan.cached) {
      highlights.push('Served from cache');
    }
    if (tech && tech.name && scan.audit && Array.isArray(scan.audit.outdated)) {
      const outdated = scan.audit.outdated.find(item => item && item.name === tech.name);
      if (outdated) {
        highlights.push('Version flagged in audit');
      }
    }
    return highlights;
  }

  function collectTechEvidenceEntries(tech) {
    if (!tech || typeof tech !== 'object') {
      return [];
    }
    const evidence = tech.evidence;
    if (Array.isArray(evidence)) {
      return evidence.filter(entry => entry && typeof entry === 'object');
    }
    if (evidence && typeof evidence === 'object') {
      return [evidence];
    }
    return [];
  }

  function normalizeEvidenceUrl(rawUrl, fallbackDomain) {
    if (rawUrl === null || rawUrl === undefined) {
      return null;
    }
    const text = String(rawUrl).trim();
    if (!text) {
      return null;
    }
    let href = text;
    let hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(text);
    if (text.startsWith('//')) {
      href = `https:${text}`;
      hasScheme = true;
    } else if (!hasScheme && fallbackDomain) {
      const cleanDomain = String(fallbackDomain).replace(/^https?:\/\//, '').split('/')[0];
      const leadingSlash = text.startsWith('/') ? '' : '/';
      href = `https://${cleanDomain}${leadingSlash}${text}`;
      hasScheme = true;
    }
    let display = text.replace(/^https?:\/\//, '');
    try {
      const parsed = new URL(hasScheme ? href : text);
      const pathPart = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '';
      const search = parsed.search && parsed.search !== '?' ? parsed.search : '';
      display = `${parsed.hostname}${pathPart}${search}` || parsed.hostname;
    } catch (_) {
      display = text.replace(/^https?:\/\//, '');
    }
    const result = { display };
    if (hasScheme) {
      result.href = href;
    }
    return result;
  }

  function collectTechSiteEntries(tech) {
    const entries = collectTechEvidenceEntries(tech);
    const scanDomain = window._latestScan && window._latestScan.domain ? window._latestScan.domain : '';
    const seen = new Set();
    const sites = [];
    const pushSite = (raw) => {
      if (raw === null || raw === undefined) {
        return;
      }
      const normalized = normalizeEvidenceUrl(raw, scanDomain);
      if (!normalized) {
        return;
      }
      const key = normalized.href || normalized.display;
      if (!key || seen.has(key)) {
        return;
      }
      seen.add(key);
      sites.push(normalized);
    };
    entries.forEach(entry => {
      if (!entry || typeof entry !== 'object') {
        return;
      }
      if (typeof entry.url === 'string' || typeof entry.url === 'number') {
        pushSite(entry.url);
      }
      if (Array.isArray(entry.urls)) {
        entry.urls.forEach(pushSite);
      }
      if (typeof entry.value === 'string' && looksLikeUrl(entry.value)) {
        pushSite(entry.value);
      }
      if (Array.isArray(entry.matches)) {
        entry.matches.forEach(match => {
          if (match && typeof match.value === 'string' && looksLikeUrl(match.value)) {
            pushSite(match.value);
          }
        });
      }
    });
    if (!sites.length && scanDomain) {
      const fallback = normalizeEvidenceUrl(`https://${scanDomain}`, scanDomain);
      if (fallback) {
        sites.push(fallback);
      }
    }
    return sites;
  }

  function renderDashboardSiteEntries(tech) {
    const sites = collectTechSiteEntries(tech);
    if (!sites.length) {
      return '<li class="dash-sites-empty">Only detected on the current scan target.</li>';
    }
    const limit = 6;
    const slice = sites.slice(0, limit);
    let html = slice.map(renderDashboardSiteEntry).join('');
    if (sites.length > limit) {
      html += `<li class="dash-sites-more">+${sites.length - limit} more entries available in raw payload.</li>`;
    }
    return html;
  }

  function renderDashboardSiteEntry(site) {
    if (!site) {
      return '';
    }
    const label = site.display || site.href || '';
    if (site.href) {
      return `<li><a class="dash-site-link" href="${attrEscape(site.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a></li>`;
    }
    return `<li><span class="dash-site-link">${escapeHtml(label)}</span></li>`;
  }

  function normalizeDomainFromApi(entry) {
    if (entry === null || entry === undefined) {
      return '';
    }
    if (typeof entry === 'string') {
      return entry.trim();
    }
    if (typeof entry === 'object' && entry.domain) {
      return String(entry.domain).trim();
    }
    return '';
  }

  function renderDashboardDbDomainEntry(domain) {
    if (!domain) {
      return '';
    }
    const trimmed = domain.trim();
    const bare = trimmed.replace(/^https?:\/\//, '');
    const hrefSource = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${bare}`;
    const evidenceKey = normalizeEvidenceDomain(trimmed) || bare.toLowerCase();
    return `<li class="dash-sites-item" data-domain="${attrEscape(evidenceKey)}">
    <div class="dash-site-entry">
      <a class="dash-site-link" href="${attrEscape(hrefSource)}" target="_blank" rel="noopener noreferrer">${escapeHtml(trimmed)}</a>
      <button type="button" class="dash-site-evidence-btn" data-domain="${attrEscape(evidenceKey)}" title="Load stored evidence for this domain">Evidence</button>
    </div>
  </li>`;
  }

  function normalizeDashboardDomainPayload(payload) {
    const rawDomains = Array.isArray(payload && payload.domains) ? payload.domains : [];
    const rawSites = Array.isArray(payload && payload.sites) ? payload.sites : [];
    const raw = rawDomains.length ? rawDomains : rawSites;
    const seen = new Set();
    const domains = [];
    raw.forEach(entry => {
      const normalized = normalizeDomainFromApi(entry);
      if (!normalized) {
        return;
      }
      const key = normalized.toLowerCase();
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      domains.push(normalized);
    });
    let total = domains.length;
    if (payload && typeof payload.count === 'number') {
      total = payload.count;
    } else if (payload && typeof payload.total === 'number') {
      total = payload.total;
    }
    return { domains, total };
  }

  function normalizeEvidenceDomain(domain) {
    const normalized = normalizeDomainFromApi(domain);
    if (!normalized) {
      return '';
    }
    return normalized.replace(/^https?:\/\//, '').replace(/\/+$/, '').toLowerCase();
  }

  function maybeAutoSelectDashboardEvidenceDomain() {
    if (dashEvidenceState.currentDomain || dashEvidenceState.pendingDomain) {
      return;
    }
    const source = (dashDomainState.filtered && dashDomainState.filtered.length)
      ? dashDomainState.filtered
      : dashDomainState.domains;
    if (source && source.length) {
      fetchDashboardEvidenceForDomain(source[0]);
    } else {
      setDashboardEvidenceFallback('Showing evidence from the latest scan payload.', 'muted');
    }
  }

  function fetchDashboardEvidenceForDomain(domain) {
    const techKey = dashEvidenceState.techKey;
    const normalizedDomain = normalizeEvidenceDomain(domain);
    if (!techKey || !normalizedDomain) {
      setDashboardEvidenceFallback('Evidence unavailable for this technology.', 'muted');
      return;
    }
    const token = ++dashEvidenceState.lastFetchToken;
    dashEvidenceState.pendingDomain = normalizedDomain;
    dashEvidenceState.currentDomain = '';
    setDashboardEvidenceSource(`Loading evidence from ${normalizedDomain}…`, 'muted');
    setDashboardEvidenceLoading();
    fetch(`/api/domain/${encodeURIComponent(normalizedDomain)}/evidence_for_tech?tech=${encodeURIComponent(techKey)}`)
      .then(res => {
        if (!res.ok) {
          throw new Error('http_error');
        }
        return res.json();
      })
      .then(payload => {
        if (token !== dashEvidenceState.lastFetchToken) {
          return;
        }
        const entries = Array.isArray(payload && payload.evidence)
          ? payload.evidence.filter(entry => entry && typeof entry === 'object')
          : [];
        if (entries.length) {
          dashEvidenceState.currentDomain = normalizedDomain;
          dashEvidenceState.pendingDomain = '';
          setDashboardEvidenceSource(`Evidence from ${normalizedDomain}`, '');
          setDashboardEvidenceEntries(entries);
          updateDashboardEvidenceActiveStyles();
        } else {
          setDashboardEvidenceFallback(`No stored evidence for ${normalizedDomain}.`, 'muted');
        }
      })
      .catch(() => {
        if (token !== dashEvidenceState.lastFetchToken) {
          return;
        }
        setDashboardEvidenceFallback('Failed to load stored evidence. Showing latest scan payload instead.', 'error');
      });
  }

  function updateDashboardEvidenceActiveStyles() {
    if (!dashTechSites) {
      return;
    }
    const active = dashEvidenceState.currentDomain;
    const items = dashTechSites.querySelectorAll('.dash-sites-item');
    items.forEach(item => {
      const domainAttr = item.getAttribute('data-domain');
      if (active && domainAttr && domainAttr.toLowerCase() === active) {
        item.classList.add('is-active');
      } else {
        item.classList.remove('is-active');
      }
    });
  }

  function updateDashboardSitesMeta(visible, total) {
    if (!dashTechSitesMeta) {
      return;
    }
    if (!total && !visible) {
      dashTechSitesMeta.textContent = 'No domains in database';
      return;
    }
    if (visible === total) {
      dashTechSitesMeta.textContent = `${visible} domains listed`;
    } else {
      dashTechSitesMeta.textContent = `${visible} of ${total} domains match`;
    }
  }

  function renderDashboardDomainList() {
    if (!dashTechSites) {
      return;
    }
    const list = dashDomainState.filtered || [];
    if (!list.length) {
      dashTechSites.innerHTML = '<li class="dash-sites-empty">No domains recorded for this technology.</li>';
      updateDashboardSitesMeta(0, dashDomainState.total || 0);
      return;
    }
    dashTechSites.innerHTML = list.map(renderDashboardDbDomainEntry).join('');
    updateDashboardSitesMeta(list.length, dashDomainState.total || list.length);
    updateDashboardEvidenceActiveStyles();
  }

  function setDashboardDomainsFromCache(cacheKey, normalized) {
    dashDomainState.currentKey = cacheKey;
    dashDomainState.domains = normalized.domains.slice();
    dashDomainState.filtered = normalized.domains.slice();
    dashDomainState.total = normalized.total;
    if (dashTechSitesFilter) {
      dashTechSitesFilter.value = '';
    }
    renderDashboardDomainList();
    maybeAutoSelectDashboardEvidenceDomain();
  }

  function applyDashboardDomainFilter(query) {
    const base = dashDomainState.domains || [];
    const q = (query || '').trim().toLowerCase();
    if (!q) {
      dashDomainState.filtered = base.slice();
    } else {
      dashDomainState.filtered = base.filter(domain => domain.toLowerCase().indexOf(q) !== -1);
    }
    renderDashboardDomainList();
  }

  function fetchDashboardDomains(techName) {
    if (!dashTechSites) {
      return;
    }
    const key = (techName || '').trim();
    if (!key) {
      dashDomainState.domains = [];
      dashDomainState.filtered = [];
      dashDomainState.total = 0;
      dashTechSites.innerHTML = '<li class="dash-sites-empty">Technology name unavailable.</li>';
      updateDashboardSitesMeta(0, 0);
      setDashboardEvidenceFallback('Technology name unavailable for evidence lookup.', 'muted');
      updateDashboardEvidenceActiveStyles();
      return;
    }
    const cacheKey = key.toLowerCase();
    if (dashDomainCache.has(cacheKey)) {
      setDashboardDomainsFromCache(cacheKey, dashDomainCache.get(cacheKey));
      return;
    }
    dashDomainState.domains = [];
    dashDomainState.filtered = [];
    dashDomainState.total = 0;
    dashTechSites.innerHTML = '<li class="dash-sites-loading">Loading domains from database…</li>';
    if (dashTechSitesMeta) {
      dashTechSitesMeta.textContent = 'Fetching domains…';
    }
    const requestUrl = `/api/tech/${encodeURIComponent(key)}/sites?limit=250`;
    fetch(requestUrl)
      .then(res => {
        if (!res.ok) {
          throw new Error('HTTP ' + res.status);
        }
        return res.json();
      })
      .then(payload => {
        const normalized = normalizeDashboardDomainPayload(payload || {});
        dashDomainCache.set(cacheKey, normalized);
        setDashboardDomainsFromCache(cacheKey, normalized);
      })
      .catch(() => {
        dashDomainState.domains = [];
        dashDomainState.filtered = [];
        dashDomainState.total = 0;
        dashTechSites.innerHTML = '<li class="dash-sites-error">Failed to load domain list from database.</li>';
        updateDashboardSitesMeta(0, 0);
        setDashboardEvidenceFallback('Failed to load domain list. Showing latest scan evidence.', 'error');
        updateDashboardEvidenceActiveStyles();
      });
  }

  if (dashTechSitesFilter) {
    dashTechSitesFilter.addEventListener('input', function () {
      applyDashboardDomainFilter(this.value);
    });
  }

  if (dashTechSites) {
    dashTechSites.addEventListener('click', function (event) {
      const target = event.target && event.target.closest ? event.target.closest('.dash-site-evidence-btn') : null;
      if (!target) {
        return;
      }
      const domain = target.getAttribute('data-domain');
      if (!domain) {
        return;
      }
      event.preventDefault();
      fetchDashboardEvidenceForDomain(domain);
    });
  }

  function highlightDashboardEvidence() {
    if (!dashTechEvidence) {
      return;
    }
    const highlightClass = 'dash-evidence-highlight';
    dashTechEvidence.classList.add(highlightClass);
    try {
      dashTechEvidence.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (_) {
      dashTechEvidence.scrollIntoView();
    }
    setTimeout(() => {
      dashTechEvidence.classList.remove(highlightClass);
    }, 1600);
  }

  function renderDashboardEvidenceEntries(tech) {
    return renderDashboardEvidenceList(collectTechEvidenceEntries(tech));
  }

  function renderDashboardEvidenceList(entries) {
    const normalizedEntries = Array.isArray(entries)
      ? entries.filter(entry => entry && typeof entry === 'object')
      : [];
    if (!normalizedEntries.length) {
      return '<li class="dash-evidence-empty">No evidence captured for this technology.</li>';
    }
    const limit = 10;
    const slice = normalizedEntries.slice(0, limit);
    let html = slice.map(entry => renderDashboardEvidenceEntry(entry)).join('');
    if (normalizedEntries.length > limit) {
      html += `<li class="dash-evidence-more">+${normalizedEntries.length - limit} more evidence entries are available in the raw payload.</li>`;
    }
    return html;
  }

  function renderDashboardEvidenceEntry(entry) {
    if (!entry || typeof entry !== 'object') {
      return '';
    }
    const handledKeys = {
      kind: true,
      source: true,
      url: true,
      urls: true,
      snippet: true,
      match: true,
      value: true,
      pattern: true,
      note: true,
      headers: true,
      matches: true,
      confidence: true
    };
    const chips = [];
    if (entry.kind) {
      chips.push(`<span class="dash-evidence-chip">${escapeHtml(String(entry.kind))}</span>`);
    }
    if (entry.source) {
      chips.push(`<span class="dash-evidence-chip dash-evidence-chip-muted">${escapeHtml(String(entry.source))}</span>`);
    }
    const header = chips.length ? `<div class="dash-evidence-meta">${chips.join('')}</div>` : '';
    const details = [];
    const scanDomain = window._latestScan && window._latestScan.domain ? window._latestScan.domain : '';
    if (entry.url) {
      const normalizedUrl = normalizeEvidenceUrl(entry.url, scanDomain);
      if (normalizedUrl && normalizedUrl.href) {
        details.push(`<a class="dash-evidence-link" href="${attrEscape(normalizedUrl.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(normalizedUrl.display)}</a>`);
      } else {
        details.push(`<span class="dash-evidence-link">${escapeHtml(String(entry.url))}</span>`);
      }
    }
    if (Array.isArray(entry.urls)) {
      const previewUrls = entry.urls
        .map(urlVal => normalizeEvidenceUrl(urlVal, scanDomain))
        .filter(Boolean)
        .slice(0, 3)
        .map(urlObj => {
          if (!urlObj) {
            return '';
          }
          if (urlObj.href) {
            return `<a class="dash-evidence-link" href="${attrEscape(urlObj.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(urlObj.display)}</a>`;
          }
          return `<span class="dash-evidence-link">${escapeHtml(urlObj.display || '')}</span>`;
        })
        .filter(Boolean);
      if (previewUrls.length) {
        details.push(`<div class="dash-evidence-links">${previewUrls.join('')}</div>`);
      }
    }
    if (entry.snippet) {
      details.push(`<code class="dash-evidence-snippet">${escapeHtml(String(entry.snippet))}</code>`);
    }
    ['match', 'value', 'pattern', 'note'].forEach(key => {
      if (entry[key] || entry[key] === 0) {
        const rawValue = entry[key];
        if (rawValue && typeof rawValue === 'object' && !Array.isArray(rawValue)) {
          return;
        }
        const val = typeof rawValue === 'string' ? rawValue : JSON.stringify(rawValue);
        details.push(`<code class="dash-evidence-attr"><span>${escapeHtml(key)}:</span> ${escapeHtml(String(val))}</code>`);
      }
    });
    if (entry.headers && typeof entry.headers === 'object') {
      details.push(`<code class="dash-evidence-attr"><span>headers:</span> ${escapeHtml(JSON.stringify(entry.headers))}</code>`);
    }
    if (Array.isArray(entry.matches)) {
      const preview = entry.matches
        .map(match => (match && typeof match.value === 'string') ? match.value : null)
        .filter(Boolean)
        .slice(0, 2);
      if (preview.length) {
        details.push(`<code class="dash-evidence-attr"><span>matches:</span> ${escapeHtml(preview.join(', '))}</code>`);
      }
    }
    Object.keys(entry).forEach(key => {
      if (handledKeys[key]) {
        return;
      }
      const raw = entry[key];
      if (raw === null || raw === undefined) {
        return;
      }
      let formatted = '';
      if (typeof raw === 'string' || typeof raw === 'number' || typeof raw === 'boolean') {
        formatted = String(raw);
      } else {
        try {
          formatted = JSON.stringify(raw);
        } catch (_) {
          formatted = String(raw);
        }
      }
      if (formatted) {
        details.push(`<code class="dash-evidence-attr"><span>${escapeHtml(key)}:</span> ${escapeHtml(formatted)}</code>`);
      }
    });
    if (!details.length) {
      details.push('<span class="dash-evidence-fallback">Additional details available in the raw JSON panel.</span>');
    }
    return `<li>${header}<div class="dash-evidence-body">${details.join('')}</div></li>`;
  }

  function populateDashboardModal(tech) {
    if (!tech) {
      return;
    }
    const techLabel = tech.name || tech.tech || tech.slug || '';
    resetDashboardEvidenceState(techLabel, tech);
    if (dashTechName) {
      dashTechName.textContent = techLabel || 'Technology';
    }
    if (dashTechSites) {
      dashTechSites.innerHTML = '<li class="dash-sites-loading">Loading domains from database…</li>';
      fetchDashboardDomains(techLabel);
    }
  }

  function handleDashModalEsc(event) {
    if (event.key === 'Escape' || event.key === 'Esc') {
      event.preventDefault();
      closeDashboardTechModal();
    }
  }

  function openDashboardTechModalByIndex(idx) {
    const techs = window._latestTechs || [];
    if (!Array.isArray(techs) || idx < 0 || idx >= techs.length) {
      return;
    }
    openDashboardTechModal(techs[idx]);
  }

  function openDashboardTechModal(tech) {
    if (!dashModal || !tech) {
      return;
    }
    dashModalLastFocus = document.activeElement;
    populateDashboardModal(tech);
    dashModal.classList.add('is-visible');
    dashModal.setAttribute('aria-hidden', 'false');
    document.body && document.body.classList.add('dash-modal-open');
    if (dashModalPanel && typeof dashModalPanel.focus === 'function') {
      requestAnimationFrame(() => {
        try {
          dashModalPanel.focus();
        } catch (_) { /* ignore */ }
      });
    }
    if (!dashModalEscHandlerAttached) {
      document.addEventListener('keydown', handleDashModalEsc, true);
      dashModalEscHandlerAttached = true;
    }
    if (dashHighlightEvidenceNext) {
      setTimeout(() => { highlightDashboardEvidence(); }, 140);
      dashHighlightEvidenceNext = false;
    }
  }

  function closeDashboardTechModal() {
    if (!dashModal || !dashModal.classList.contains('is-visible')) {
      return;
    }
    dashModal.classList.remove('is-visible');
    dashModal.setAttribute('aria-hidden', 'true');
    document.body && document.body.classList.remove('dash-modal-open');
    if (dashModalEscHandlerAttached) {
      document.removeEventListener('keydown', handleDashModalEsc, true);
      dashModalEscHandlerAttached = false;
    }
    if (dashModalLastFocus && typeof dashModalLastFocus.focus === 'function') {
      try { dashModalLastFocus.focus(); } catch (_) { /* ignore */ }
    }
    dashModalLastFocus = null;
  }

  function activateTechCard(card) {
    if (!card) {
      return false;
    }
    const idxAttr = card.getAttribute('data-idx');
    const idx = idxAttr !== null ? parseInt(idxAttr, 10) : NaN;
    if (Number.isNaN(idx)) {
      return false;
    }
    openDashboardTechModalByIndex(idx);
    return true;
  }

  function onTechCardClick(event) {
    const card = event.target && event.target.closest ? event.target.closest('.tech-card') : null;
    if (!card) {
      return;
    }
    const pillClicked = event.target.closest ? event.target.closest('.tech-confidence-pill') : null;
    dashHighlightEvidenceNext = Boolean(pillClicked);
    event.preventDefault();
    const opened = activateTechCard(card);
    if (!opened) {
      dashHighlightEvidenceNext = false;
    }
  }

  function onTechCardKeydown(event) {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    const target = event.target;
    const card = target && target.closest ? target.closest('.tech-card') : null;
    if (!card) {
      return;
    }
    const pillFocused = target && target.closest ? target.closest('.tech-confidence-pill') : null;
    dashHighlightEvidenceNext = Boolean(pillFocused);
    event.preventDefault();
    const opened = activateTechCard(card);
    if (!opened) {
      dashHighlightEvidenceNext = false;
    }
  }

  if (categoryGroups) {
    categoryGroups.addEventListener('click', onTechCardClick);
    categoryGroups.addEventListener('keydown', onTechCardKeydown);
  }
  if (dashModalOverlay) {
    dashModalOverlay.addEventListener('click', closeDashboardTechModal);
  }
  if (dashModalClose) {
    dashModalClose.addEventListener('click', closeDashboardTechModal);
  }


  function formatMs(value) {
    const ms = Number(value);
    if (!Number.isFinite(ms) || ms < 0) {
      return '';
    }
    if (ms < 1000) {
      return `${Math.round(ms)} ms`;
    }
    const seconds = ms / 1000;
    if (seconds < 60) {
      return seconds < 10 ? `${seconds.toFixed(1)} s` : `${Math.round(seconds)} s`;
    }
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.round(seconds % 60);
    if (minutes < 60) {
      if (!remainingSeconds) {
        return `${minutes} m`;
      }
      return `${minutes} m ${remainingSeconds} s`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    if (!remainingMinutes) {
      return `${hours} h`;
    }
    return `${hours} h ${remainingMinutes} m`;
  }

  function formatBytes(value) {
    if (value === null || value === undefined) {
      return '';
    }
    let bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) {
      return '';
    }
    if (bytes === 0) {
      return '0 B';
    }
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    while (bytes >= 1024 && unitIndex < units.length - 1) {
      bytes /= 1024;
      unitIndex += 1;
    }
    const precision = bytes >= 10 ? 1 : 2;
    return `${bytes.toFixed(precision)} ${units[unitIndex]}`;
  }

  function renderPhaseBreakdown(phases) {
    if (!phaseBreakdownEl) { return; }
    const defs = [
      { key: 'heuristic_ms', label: 'Heuristic' },
      { key: 'engine_ms', label: 'Fingerprint' },
      { key: 'synthetic_ms', label: 'Synthetic' },
      { key: 'micro_ms', label: 'Micro fallback' },
      { key: 'node_full_ms', label: 'Node fallback' },
      { key: 'version_audit_ms', label: 'Version audit' }
    ];
    const chips = [];
    if (phases && typeof phases === 'object') {
      defs.forEach(def => {
        const rawVal = phases[def.key];
        const val = Number.isFinite(rawVal) ? rawVal : parseInt(rawVal, 10);
        if (Number.isFinite(val) && val > 0) {
          chips.push(`<span class="phase-chip"><strong>${def.label}</strong><span class="phase-meta">${formatMs(val)}</span></span>`);
        }
      });
    }
    if (!chips.length) {
      phaseBreakdownEl.style.display = 'none';
      phaseBreakdownEl.innerHTML = '';
      return;
    }
    phaseBreakdownEl.innerHTML = chips.join('');
    phaseBreakdownEl.style.display = 'flex';
  }

  function resetScanProgress() {
    if (progressResetTimer) {
      clearTimeout(progressResetTimer);
      progressResetTimer = null;
    }
    if (progressState && progressState.rafId) {
      cancelAnimationFrame(progressState.rafId);
    }
    progressState = null;
    if (progressBarEl) {
      progressBarEl.style.width = '0%';
    }
    if (progressLabelEl) {
      progressLabelEl.textContent = scanBtnOriginalText;
    }
    if (progressEtaEl) {
      progressEtaEl.textContent = '';
    }
  }

  function ensureButtonProgressShell() {
    if (!scanBtn.querySelector('.btn-progress-shell')) {
      scanBtn.innerHTML = '';
      const shell = document.createElement('span');
      shell.className = 'btn-progress-shell';
      const bar = document.createElement('span');
      bar.className = 'btn-inner-bar';
      const text = document.createElement('span');
      text.className = 'btn-progress-text';
      const eta = document.createElement('span');
      eta.className = 'btn-progress-eta';
      shell.append(bar, text, eta);
      scanBtn.append(shell);
      progressBarEl = bar;
      progressLabelEl = text;
      progressEtaEl = eta;
    }
  }

  function updateScanProgressVisual(fraction) {
    if (!progressBarEl) { return; }
    const clamped = Math.max(0.03, Math.min(1, fraction));
    progressBarEl.style.width = `${(clamped * 100).toFixed(2)}%`;
    if (progressState && progressLabelEl) {
      const steps = progressState.steps;
      let active = steps[steps.length - 1];
      for (const step of steps) {
        if (clamped <= step.threshold) {
          active = step;
          break;
        }
      }
      // keep text short inside button
      progressLabelEl.textContent = active.label;
    }
    if (progressState && progressEtaEl) {
      const elapsed = performance.now() - progressState.startedAt;
      const remaining = Math.max(0, progressState.estimatedMs - elapsed);
      const remainingSeconds = Math.max(0, Math.round(Math.max(remaining, 400) / 1000));
      progressEtaEl.textContent = clamped < 0.92 && remainingSeconds > 0 ? `~${remainingSeconds}s` : '';
    }
  }

  function startScanProgress() {
    resetScanProgress();
    ensureButtonProgressShell();
    if (!progressBarEl) { return; }
    const steps = [
      { threshold: 0.2, label: 'Heuristic fingerprinting' },
      { threshold: 0.5, label: 'Fingerprint engine' },
      { threshold: 0.7, label: 'Synthetic enrichment' },
      { threshold: 0.9, label: 'Fallback checks' },
      { threshold: 1, label: 'Finalizing' }
    ];
    progressState = {
      startedAt: performance.now(),
      estimatedMs: 8000,
      rafId: null,
      steps,
      done: false
    };
    const tick = () => {
      if (!progressState || progressState.done) { return; }
      const elapsed = performance.now() - progressState.startedAt;
      const fraction = Math.min(0.94, elapsed / progressState.estimatedMs);
      updateScanProgressVisual(fraction);
      progressState.rafId = requestAnimationFrame(tick);
    };
    progressState.rafId = requestAnimationFrame(tick);
  }

  function completeScanProgress(result) {
    if (progressState && progressState.rafId) {
      cancelAnimationFrame(progressState.rafId);
    }
    progressState = null;
    if (progressBarEl) {
      progressBarEl.style.width = '100%';
    }
    if (progressLabelEl) {
      progressLabelEl.textContent = 'Done';
    }
    const durationMs = computeActualDurationMs(result);
    if (progressEtaEl) {
      progressEtaEl.textContent = durationMs ? `${(durationMs / 1000).toFixed(1)}s` : '';
    }
    renderPhaseBreakdown(result && result.phases);
    progressResetTimer = setTimeout(() => { resetScanProgress(); }, 6000);
  }

  function failScanProgress(message) {
    if (progressState && progressState.rafId) {
      cancelAnimationFrame(progressState.rafId);
    }
    progressState = null;
    if (progressBarEl) {
      progressBarEl.style.width = '100%';
    }
    if (progressLabelEl) {
      progressLabelEl.textContent = message || 'Scan failed';
    }
    if (progressEtaEl) {
      progressEtaEl.textContent = '';
    }
    if (phaseBreakdownEl) {
      phaseBreakdownEl.style.display = 'none';
      phaseBreakdownEl.innerHTML = '';
    }
    progressResetTimer = setTimeout(() => { resetScanProgress(); }, 4000);
  }

  function resetScanButtonVisual() {
    scanBtn.classList.remove('is-loading');
    scanBtn.disabled = false;
    scanBtn.removeAttribute('aria-busy');
    scanBtn.textContent = scanBtnOriginalText;
  }

  function setLoading(flag) {
    if (flag) {
      scanBtn.classList.add('is-loading');
      scanBtn.disabled = true;
      scanBtn.setAttribute('aria-busy', 'true');
      ensureButtonProgressShell();
      progressLabelEl.textContent = 'Init';
      progressEtaEl.textContent = '';
      statusLine.textContent = 'Scanning...';
      startScanProgress();
    } else {
      resetScanButtonVisual();
      if (statusLine.textContent === 'Scanning...') {
        statusLine.textContent = '';
      }
    }
  }

  // Normalize technology names to merge duplicates (e.g., PWA → Progressive Web App, nginx → Nginx)
  const TECH_NAME_NORMALIZE_MAP = {
    'pwa': 'Progressive Web App',
    'nginx': 'Nginx',
    'apache': 'Apache',
    'mysql': 'MySQL',
    'postgresql': 'PostgreSQL',
    'mongodb': 'MongoDB',
    'redis': 'Redis',
    'php': 'PHP',
    'jquery': 'jQuery',
    'wordpress': 'WordPress',
    'joomla': 'Joomla',
    'drupal': 'Drupal',
    'react': 'React',
    'vue.js': 'Vue.js',
    'angular': 'Angular',
    'node.js': 'Node.js',
    'express': 'Express',
    'laravel': 'Laravel',
    'django': 'Django',
    'flask': 'Flask',
    'bootstrap': 'Bootstrap',
    'tailwind css': 'Tailwind CSS',
    'cloudflare': 'Cloudflare',
    'google analytics': 'Google Analytics',
    'google tag manager': 'Google Tag Manager'
  };

  function normalizeTechName(name) {
    if (!name || typeof name !== 'string') return name;
    const trimmed = name.trim();
    const lower = trimmed.toLowerCase();
    return TECH_NAME_NORMALIZE_MAP[lower] || trimmed;
  }

  // Fallback categories for common technologies missing categories in scan results
  const TECH_CATEGORY_FALLBACK = {
    // Programming Languages
    'php': 'Programming Languages',
    'python': 'Programming Languages',
    'ruby': 'Programming Languages',
    'java': 'Programming Languages',
    'go': 'Programming Languages',
    // Databases
    'mysql': 'Databases',
    'postgresql': 'Databases',
    'mongodb': 'Databases',
    'redis': 'Databases',
    'mariadb': 'Databases',
    // JavaScript Libraries
    'jquery': 'JavaScript Libraries',
    'jquery ui': 'JavaScript Libraries',
    'jquery migrate': 'JavaScript Libraries',
    'core-js': 'JavaScript Libraries',
    'moment.js': 'JavaScript Libraries',
    'swiper': 'JavaScript Libraries',
    'marked': 'JavaScript Libraries',
    'popper': 'JavaScript Libraries',
    'popper.js': 'JavaScript Libraries',
    'lodash': 'JavaScript Libraries',
    'axios': 'JavaScript Libraries',
    // UI Frameworks
    'bootstrap': 'UI Frameworks',
    'tailwind css': 'UI Frameworks',
    'bulma': 'UI Frameworks',
    'foundation': 'UI Frameworks',
    'materialize css': 'UI Frameworks',
    // JavaScript Frameworks
    'react': 'JavaScript Frameworks',
    'vue.js': 'JavaScript Frameworks',
    'angular': 'JavaScript Frameworks',
    'svelte': 'JavaScript Frameworks',
    'next.js': 'JavaScript Frameworks',
    // Tag Managers
    'google tag manager': 'Tag Managers',
    // Web Servers
    'nginx': 'Web Servers',
    'apache': 'Web Servers',
    'apache http server': 'Web Servers',
    'litespeed': 'Web Servers',
    'microsoft iis': 'Web Servers',
    // Operating Systems
    'ubuntu': 'Operating Systems',
    'debian': 'Operating Systems',
    'centos': 'Operating Systems',
    'windows server': 'Operating Systems',
    // Font Scripts
    'font awesome': 'Font Scripts',
    'font awesome 4': 'Font Scripts',
    'font awesome 5': 'Font Scripts',
    'font awesome 6': 'Font Scripts',
    'google font api': 'Font Scripts',
    'twitter emoji (twemoji)': 'Font Scripts',
    // Push Notifications
    'onesignal': 'Marketing Automation',
    // WordPress Plugins
    'wpml': 'WordPress Plugins',
    'wordpress multilingual plugin (wpml)': 'WordPress Plugins',
    'draftpress hfcm': 'WordPress Plugins',
    'essential addons for elementor': 'WordPress Plugins',
    'yoast seo': 'SEO',
    'elementor': 'Page Builders',
    // CMS
    'wordpress': 'CMS',
    'joomla': 'CMS',
    'drupal': 'CMS',
    // PWA
    'pwa': 'Progressive Web Apps',
    'progressive web app': 'Progressive Web Apps',
    // SSL/TLS
    'sectigo': 'SSL/TLS Certificate Authorities',
    "let's encrypt": 'SSL/TLS Certificate Authorities',
    'digicert': 'SSL/TLS Certificate Authorities',
    // CDN
    'cloudflare': 'CDN',
    'jsdelivr': 'CDN',
    // Security
    'hsts': 'Security',
    // Analytics
    'google analytics': 'Analytics',
    'google analytics ga4': 'Analytics'
  };

  function getFallbackCategory(techName) {
    if (!techName) return null;
    return TECH_CATEGORY_FALLBACK[String(techName).toLowerCase()] || null;
  }

  function techCard(t, outdated, idx) {
    const catsArr = normalizeCategories(t.categories);
    const primary = getPrimaryCategory(t);
    const fallbackCategory = typeof t.category === 'string' ? t.category.trim() : '';
    // If no categories, try fallback lookup by tech name
    const fallbackFromName = getFallbackCategory(t.name);
    const categoryList = catsArr.length ? catsArr : (fallbackCategory ? [fallbackCategory] : (fallbackFromName ? [fallbackFromName] : []));
    const cats = categoryList.join(', ');
    const primaryAttr = attrEscape(primary || 'Other');
    const iconSlug = mapTechToIcon(t.name);
    const readableName = (t.name || '').trim();
    const tooltip = attrEscape(`${readableName}${t.version ? ' v' + t.version : ''}\n${cats || ''}`);
    const safeNameAttr = attrEscape(readableName);
    const fallback = fallbackInitials(readableName).replace(/"/g, '');
    const safeAlt = attrEscape(readableName);
    const innerIcon = iconSlug
      ? `<img src="${ICON_BASES[0]}/${iconSlug}.svg" alt="${safeAlt}" loading="lazy" style="width:18px;height:18px;display:block;" data-fallback="${fallback}" data-slug="${iconSlug}" data-icon-source-index="0" onerror="window.handleTechIconError && window.handleTechIconError(this);" />`
      : fallback;
    let confidenceVal = null;
    if (typeof t.confidence === 'number' && Number.isFinite(t.confidence)) {
      confidenceVal = Math.round(t.confidence);
    } else {
      const parsed = parseInt(t.confidence, 10);
      if (Number.isFinite(parsed)) {
        confidenceVal = parsed;
      }
    }
    const idxAttr = typeof idx === 'number' && Number.isFinite(idx) ? ` data-idx="${idx}"` : '';
    const confidencePill = confidenceVal !== null
      ? `<span class="tech-confidence-pill" aria-label="Confidence ${confidenceVal}%" role="button" tabindex="0" data-evidence-trigger="true" title="Click to view detection evidence"><span class="tech-pill-label">Confidence</span><span class="tech-pill-value">${confidenceVal}%</span></span>`
      : '';
    const catsDisplay = cats ? escapeHtml(cats) : '(no categories)';
    const metaPieces = [catsDisplay];
    if (confidencePill) { metaPieces.push(confidencePill); }
    const metaInner = metaPieces.join('<span class="tech-meta-sep" aria-hidden="true">&bull;</span>');
    const ariaLabel = attrEscape(readableName ? `View ${readableName} details` : 'View technology details');
    return `<div class="tech-card${outdated ? ' tech-outdated' : ''}" data-cat="${primaryAttr}" data-tech="${safeNameAttr}"${idxAttr} role="button" tabindex="0" aria-label="${ariaLabel}" title="${tooltip}">` +
      `<div class="tech-card-header">` +
      `<span class="tech-icon" data-icon="${iconSlug || ''}">${innerIcon}</span>` +
      `<h5>${t.name}${t.version ? ' <span class="version-badge">' + t.version + '</span>' : ''}</h5>` +
      `</div>` +
      `<div class="tech-meta">${metaInner}</div>` +
      `</div>`;
  }







  // Mapping tech names (lowercase) to tech-stack-icons slug
  const ICON_BASES = [
    '/static/icons/tech',
    'https://unpkg.com/tech-stack-icons@3.3.2/icons'
  ];

  const ICON_MAP = {
    'wordpress': 'wordpress',
    'react': 'react',
    'next.js': 'nextjs',
    'nextjs': 'nextjs',
    'nginx': 'nginx',
    'apache': 'apache',
    'laravel': 'laravel',
    'django': 'django',
    'tailwind css': 'tailwindcss',
    'tailwindcss': 'tailwindcss',
    'bootstrap': 'bootstrap5',
    'jquery': 'jquery',
    'express': 'express',
    'express.js': 'express',
    'vue.js': 'vuejs',
    'vue.js framework': 'vuejs',
    'vue': 'vuejs',
    'angularjs': 'angular',
    'angular.js': 'angular',
    'angular': 'angular',
    'nuxt.js': 'nuxtjs',
    'nuxt': 'nuxtjs',
    'svelte': 'svelte',
    'php': 'php',
    'python': 'python',
    'node.js': 'nodejs',
    'nodejs': 'nodejs',
    'mysql': 'mysql',
    'postgresql': 'postgresql',
    'mongodb': 'mongodb',
    'redis': 'redis',
    'firebase': 'firebase',
    'google analytics': 'google',
    'google analytics (ua)': 'google',
    'google analytics (ga4)': 'google',
    'google tag manager': 'google',
    'google font api': 'google',
    'google fonts': 'google',
    'font awesome': 'fontawesome',
    'rss': 'rss',
    'yoast seo': 'yoast',
    'moment.js': 'momentjs',
    'momentjs': 'momentjs',
    'swiper': 'swiper',
    'swiper slider': 'swiper',
    'onesignal': 'onesignal',
    'twemoji': 'twemoji',
    'twitter emoji (twemoji)': 'twemoji',
    'core-js': 'corejs',
    'corejs': 'corejs',
    'wpml': 'wpml',
    'elementor': 'elementor',
    'javascript': 'js',
    'css': 'css3',
    'css3': 'css3',
    'html': 'html5',
    'html5': 'html5',
    'typescript': 'typescript',
    'sass': 'sass',
    'scss': 'sass',
    'c++': 'cplusplus',
    'c#': 'csharp',
    '.net': 'dotnet',
    'asp.net': 'netcore',
    'elasticsearch': 'elastic',
    'aws': 'aws',
    'azure': 'azure',
    'cloudflare': 'cloudflare'
  };

  function sanitizeIconSlug(name) {
    return name
      .toLowerCase()
      .replace(/&/g, 'and')
      .replace(/\s*\(.*?\)\s*/g, ' ')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }

  function mapTechToIcon(name) {
    if (!name) return null;
    const raw = String(name).trim();
    if (!raw) return null;
    const lower = raw.toLowerCase();
    if (ICON_MAP[lower]) return ICON_MAP[lower];
    const sanitized = sanitizeIconSlug(raw);
    if (ICON_MAP[sanitized]) return ICON_MAP[sanitized];
    return sanitized || null;
  }

  function fallbackInitials(name) {
    const letters = (name || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 2).toUpperCase();
    if (letters) return letters;
    const first = (name || '').trim().slice(0, 1).toUpperCase();
    return first || '•';
  }

  // Normalize category names to consistent format (eliminates duplicates like 'JavaScript libraries' vs 'JavaScript Libraries')
  const CATEGORY_NORMALIZE_MAP = {
    'javascript libraries': 'JavaScript Libraries',
    'javascript library': 'JavaScript Libraries',
    'javascript frameworks': 'JavaScript Frameworks',
    'javascript framework': 'JavaScript Frameworks',
    'web servers': 'Web Servers',
    'web server': 'Web Servers',
    'wordpress plugins': 'WordPress Plugins',
    'wordpress plugin': 'WordPress Plugins',
    'wordpress themes': 'WordPress Themes',
    'wordpress theme': 'WordPress Themes',
    'font scripts': 'Font Scripts',
    'font script': 'Font Scripts',
    'progressive web apps': 'Progressive Web Apps',
    'progressive web app': 'Progressive Web Apps',
    'pwa': 'Progressive Web Apps',
    'reverse proxies': 'Reverse Proxies',
    'reverse proxy': 'Reverse Proxies',
    'content management systems': 'CMS',
    'content management system': 'CMS',
    'cms': 'CMS',
    'programming languages': 'Programming Languages',
    'programming language': 'Programming Languages',
    'databases': 'Databases',
    'database': 'Databases',
    'tag managers': 'Tag Managers',
    'tag manager': 'Tag Managers',
    'ui frameworks': 'UI Frameworks',
    'ui framework': 'UI Frameworks',
    'css frameworks': 'CSS Frameworks',
    'css framework': 'CSS Frameworks',
    'analytics': 'Analytics',
    'security': 'Security',
    'seo': 'SEO',
    'cdn': 'CDN',
    'miscellaneous': 'Miscellaneous',
    'accessibility': 'Accessibility',
    'performance': 'Performance',
    'live chat': 'Live Chat',
    'marketing automation': 'Marketing Automation',
    'advertising': 'Advertising',
    'ecommerce': 'E-commerce',
    'e-commerce': 'E-commerce'
  };

  function normalizeCategoryName(cat) {
    if (!cat || typeof cat !== 'string') return cat;
    const trimmed = cat.trim();
    const lower = trimmed.toLowerCase();
    return CATEGORY_NORMALIZE_MAP[lower] || trimmed;
  }

  function normalizeCategories(value) {
    if (Array.isArray(value)) {
      return value
        .map(item => typeof item === 'string' ? normalizeCategoryName(item) : '')
        .filter(Boolean);
    }
    if (typeof value === 'string') {
      return value
        .split(/[;,]/)
        .map(item => normalizeCategoryName(item))
        .filter(Boolean);
    }
    return [];
  }

  function getPrimaryCategory(tech) {
    if (!tech || typeof tech !== 'object') {
      return 'Other';
    }
    const categories = normalizeCategories(tech.categories);
    if (categories.length) {
      return categories[0];
    }
    if (typeof tech.category === 'string' && tech.category.trim()) {
      return tech.category.trim();
    }
    // Try fallback lookup by technology name
    const fallback = getFallbackCategory(tech.name);
    return fallback || 'Other';
  }

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

  function attrEscape(value) {
    return escapeHtml(value).replace(/\n/g, '&#10;');
  }

  function unescapeHtml(value) {
    return String(value ?? '').replace(/&(amp|lt|gt|quot|#39);/g, function (match) {
      switch (match) {
        case '&amp;': return '&';
        case '&lt;': return '<';
        case '&gt;': return '>';
        case '&quot;': return '"';
        case '&#39;': return "'";
        default: return match;
      }
    }).replace(/&#10;/g, '\n');
  }

  function looksLikeUrl(value) {
    try {
      return /^https?:\/\//i.test(String(value || ''));
    } catch (_) {
      return false;
    }
  }

  function buildSnippetForUrl(rawUrl) {
    const url = (rawUrl || '').toString().trim();
    if (!url) { return null; }
    if (/\.css(\?|$)/i.test(url)) {
      return `<link rel="stylesheet" href="${url}">`;
    }
    if (/\.js(\?|$)/i.test(url)) {
      return `<script src="${url}" defer><\/script>`;
    }
    if (/\.(woff2?|woff|ttf|otf|eot)(\?|$)/i.test(url)) {
      const ext = (url.split('?')[0].split('.').pop() || '').toLowerCase();
      const fontMimeMap = {
        'woff2': 'font/woff2',
        'woff': 'font/woff',
        'ttf': 'font/ttf',
        'otf': 'font/otf',
        'eot': 'application/vnd.ms-fontobject'
      };
      const mime = fontMimeMap[ext] || 'font/woff2';
      return `<link rel="preload" href="${url}" as="font" type="${mime}" crossorigin>`;
    }
    return `<link rel="preload" href="${url}" as="fetch">`;
  }

  function createClientRequestToken(prefix = 'req') {
    const base = typeof prefix === 'string' && prefix.trim() ? prefix.trim() : 'req';
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return `${base}-${crypto.randomUUID()}`;
    }
    const ts = Date.now().toString(36);
    const rand = Math.random().toString(36).slice(2, 10);
    return `${base}-${ts}-${rand}`;
  }

  function uniqueList(values) {
    if (!Array.isArray(values)) {
      if (values === undefined || values === null) {
        return [];
      }
      values = [values];
    }
    const seen = new Set();
    const out = [];
    values.forEach(item => {
      if (item === null || item === undefined) {
        return;
      }
      const text = String(item).trim();
      if (!text || seen.has(text)) {
        return;
      }
      seen.add(text);
      out.push(text);
    });
    return out;
  }

  function computeActualDurationMs(result) {
    if (!result || typeof result !== 'object') {
      return null;
    }
    // PRIORITY 1: Calculate from timestamps (most accurate for total scan time)
    const started = normaliseTimestamp(result.started_at ?? result.startedAt ?? result.timestamp);
    const finished = normaliseTimestamp(result.finished_at ?? result.finishedAt ?? result.completed_at ?? result.completedAt);
    if (started !== null && finished !== null && finished >= started) {
      return finished - started;
    }
    // PRIORITY 2: Use duration_ms if available
    const durationMs = Number(result.duration_ms);
    if (Number.isFinite(durationMs) && durationMs >= 0) {
      return durationMs;
    }
    // PRIORITY 3: Use duration in seconds
    const durationSeconds = Number(result.duration);
    if (Number.isFinite(durationSeconds) && durationSeconds >= 0) {
      return durationSeconds * 1000;
    }
    return null;

    function normaliseTimestamp(value) {
      if (value === null || value === undefined) {
        return null;
      }
      let num = Number(value);
      if (!Number.isFinite(num)) {
        return null;
      }
      if (num > 1e12) {
        return Math.round(num);
      }
      if (num > 1e9) {
        return Math.round(num * 1000);
      }
      if (num >= 1e6) {
        return Math.round(num);
      }
      return Math.round(num * 1000);
    }
  }

  function logSingleCancel(domain, token) {
    const payload = { reason: 'client_cancel' };
    if (domain) {
      payload.domain = String(domain).trim();
    }
    const tokens = uniqueList(token ? [token] : []);
    if (tokens.length === 1) {
      payload.token = tokens[0];
    } else if (tokens.length > 1) {
      payload.tokens = tokens;
    }
    fetch('/scan/cancelled', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(() => { });
  }

  singleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(singleForm);
    const domain = (fd.get('domain') || '').trim();
    if (!domain) {
      singleRequestToken = null;
      return;
    }
    const fast_full = fd.get('fast_full') ? 1 : 0;
    errorBox.style.display = 'none';
    resultsBox.style.display = 'none';
    categoryGroups.innerHTML = ''; rawPre.textContent = ''; metaLine.textContent = '';
    const requestToken = createClientRequestToken('single');
    singleRequestToken = requestToken;
    setLoading(true);

    let data;
    try {
      // Abort previous in-flight single scan if any
      if (singleController) { try { singleController.abort(); } catch (_) { } }
      singleController = new AbortController();

      // Submit async job
      const submitRes = await fetch('/scan/async', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, fast_full }),
        signal: singleController.signal
      });
      const submitData = await submitRes.json();
      if (!submitRes.ok) { throw new Error(submitData.error || ('HTTP ' + submitRes.status)); }

      const jobId = submitData.job_id;
      if (!jobId) { throw new Error('No job_id returned'); }

      // Save to localStorage for recovery if user navigates away
      if (window.TechScanJobs) {
        window.TechScanJobs.addPendingJob(jobId, 'single', domain);
      }

      statusLine.textContent = 'Processing...';

      // Poll for job completion
      let completed = false;
      let pollCount = 0;
      const maxPolls = 120; // 2 minutes max

      while (!completed && pollCount < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // 1 second interval
        pollCount++;

        try {
          const statusRes = await fetch(`/api/job/${jobId}`, { signal: singleController.signal });
          if (!statusRes.ok) { continue; }
          const jobStatus = await statusRes.json();

          if (jobStatus.status === 'completed') {
            completed = true;
            // Remove from pending since we got result
            if (window.TechScanJobs) {
              window.TechScanJobs.removePendingJob(jobId);
            }
            // Fetch full result from database
            const resultRes = await fetch(`/domain?domain=${encodeURIComponent(domain)}`);
            if (resultRes.ok) {
              data = await resultRes.json();
            } else {
              // Use result from job if available
              data = jobStatus.result || { domain, technologies: [] };
            }
          } else if (jobStatus.status === 'failed') {
            throw new Error(jobStatus.error || 'Scan failed');
          } else {
            // Update progress display
            const progress = jobStatus.progress || 0;
            statusLine.textContent = `Processing... ${progress}%`;
          }
        } catch (pollErr) {
          if (pollErr.name === 'AbortError') { throw pollErr; }
          console.warn('Poll error:', pollErr);
        }
      }

      if (!completed) {
        statusLine.textContent = 'Scan running in background. Check Websites page for results.';
        setLoading(false);
        return;
      }

    } catch (err) {
      if (err.name === 'AbortError') {
        failScanProgress('Cancelled');
        setLoading(false);
        errorBox.style.display = 'none';
        statusLine.textContent = 'Cancelled';
        logSingleCancel(domain, singleRequestToken);
        singleRequestToken = null;
        singleController = null;
        return;
      }
      errorBox.textContent = 'Error: ' + err.message;
      errorBox.style.display = 'block';
      failScanProgress('Scan failed');
      setLoading(false);
      singleRequestToken = null;
      singleController = null;
      return;
    }
    const durationMs = computeActualDurationMs(data);
    completeScanProgress(data);
    setLoading(false);
    statusLine.textContent = 'Completed';
    singleRequestToken = null;
    singleController = null;
    // Meta summary
    const techs = data.technologies || [];
    // Store latest scan payload so the dashboard modal can read it
    try {
      window._latestScan = data;
      window._latestTechs = techs;
    } catch (_) { }
    const techIndexMap = new Map();
    techs.forEach((tech, idx) => {
      if (!tech || typeof tech !== 'object') {
        return;
      }
      try {
        tech.__dashIdx = idx;
      } catch (_) { /* ignore assignment failures */ }
      techIndexMap.set(tech, idx);
    });
    const outdatedMeta = (data.audit && data.audit.outdated) ? data.audit.outdated : [];
    const outdatedNames = new Set(outdatedMeta.map(o => o.name));
    const durationSeconds = (typeof data.duration === 'number' && Number.isFinite(data.duration))
      ? data.duration
      : (typeof durationMs === 'number' && Number.isFinite(durationMs) ? (durationMs / 1000) : null);
    const durationText = durationSeconds !== null && durationSeconds !== undefined
      ? `${durationSeconds.toFixed(2)}s`
      : 'n/a';
    const payloadText = formatBytes(data.payload_bytes);
    metaLine.innerHTML = `<span>Domain: <strong>${data.domain}</strong></span>` +
      `<span>Technologies: ${techs.length}</span>` +
      `<span>Duration: ${durationText}</span>` +
      `<span>Payload: ${payloadText || 'n/a'}</span>` +
      (data.cached ? '<span>Cached</span>' : '');
    if (techs.length) {
      // Deduplicate technologies by normalized name (merge PWA + Progressive Web App, nginx + Nginx, etc.)
      const seenNormalized = new Map();
      const deduplicatedTechs = [];
      techs.forEach(t => {
        if (!t || typeof t !== 'object') return;
        const rawName = (t.name || '').trim();
        const normalizedName = normalizeTechName(rawName);
        const normalizedLower = normalizedName.toLowerCase();

        if (seenNormalized.has(normalizedLower)) {
          // Already seen this tech, merge by keeping higher confidence or versioned one
          const existing = seenNormalized.get(normalizedLower);
          const existingConf = Number(existing.confidence) || 0;
          const currentConf = Number(t.confidence) || 0;
          const existingHasVersion = !!existing.version;
          const currentHasVersion = !!t.version;

          // Prefer versioned, then higher confidence
          if ((currentHasVersion && !existingHasVersion) ||
            (!existingHasVersion && !currentHasVersion && currentConf > existingConf)) {
            // Replace with current
            const idx = deduplicatedTechs.indexOf(existing);
            if (idx > -1) {
              t.name = normalizedName; // Use normalized name
              deduplicatedTechs[idx] = t;
              seenNormalized.set(normalizedLower, t);
            }
          }
          // Otherwise keep existing
        } else {
          // First time seeing this tech
          t.name = normalizedName; // Normalize name
          seenNormalized.set(normalizedLower, t);
          deduplicatedTechs.push(t);
        }
      });

      // Group by first category (normalized)
      const groups = {};
      deduplicatedTechs.forEach(t => {
        const cat = getPrimaryCategory(t);
        const key = cat || 'Other';
        (groups[key] = groups[key] || []).push(t);
      });
      const ordered = Object.keys(groups).sort((a, b) => a.localeCompare(b));
      const otherIndex = ordered.indexOf('Other');
      if (otherIndex > -1 && otherIndex !== ordered.length - 1) {
        ordered.splice(otherIndex, 1);
        ordered.push('Other');
      }
      categoryGroups.innerHTML = ordered.map(cat => {
        const cards = groups[cat].map(t => {
          const idx = techIndexMap.has(t)
            ? techIndexMap.get(t)
            : (typeof t.__dashIdx === 'number' ? t.__dashIdx : techs.indexOf(t));
          return techCard(t, outdatedNames.has(t.name), idx);
        }).join('');
        const safeCat = escapeHtml(cat);
        return `<div class="category-group"><h4>${safeCat}</h4><div class="tech-grid">${cards}</div></div>`;
      }).join('');
    } else {
      categoryGroups.innerHTML = '<div class="small-note">(No technologies detected)</div>';
    }
    rawPre.textContent = JSON.stringify(data, null, 2);
    resultsBox.style.display = 'block';
    resultsBox.classList.add('fade-in');
  });

  // Bulk handling (queue mode + validations + progress + table output)
  const bulkForm = document.getElementById('bulk-scan-form');
  const bulkBtn = document.getElementById('bulk-btn');
  const bulkCancel = document.getElementById('bulk-cancel');
  const bulkFile = document.getElementById('bulk-file');
  const fileInfo = document.getElementById('file-info');
  const bulkDownloadBottom = document.getElementById('bulk-download-bottom');
  const bulkError = document.getElementById('bulk-error');
  const bulkTableWrapper = document.getElementById('bulk-table-wrapper');
  const bulkTbody = document.getElementById('bulk-tbody');
  const bulkProgress = document.getElementById('bulk-progress');
  const bulkProgressText = document.getElementById('bulk-progress-text');
  const progressWrapper = document.querySelector('.progress-wrapper');
  const bulkProgressInd = document.getElementById('bulk-progress-ind');
  const bulkStats = document.getElementById('bulk-stats');
  const bulkErrorSummary = document.getElementById('bulk-error-summary');
  let lastBatchId = null;
  let queueAbort = false;
  let queueResults = [];
  let bulkController = null;
  let bulkPctSpan = null;
  let bulkLabelSpan = null;
  let currentBulkDomains = [];
  let bulkProcessedCount = 0;
  let currentBulkTokens = [];
  let bulkRunToken = null;

  function setupBulkButton(label, { gradient = 'linear-gradient(90deg,#10b981,#4ade80)', showPercent = true, indeterminate = false } = {}) {
    bulkBtn.style.position = 'relative';
    bulkBtn.innerHTML = '';
    const bar = document.createElement('span');
    bar.className = 'btn-progress';
    Object.assign(bar.style, { position: 'absolute', inset: '0', width: '0%', background: gradient, borderRadius: 'inherit', zIndex: '0', transition: 'width .2s ease' });
    const fg = document.createElement('span');
    fg.className = 'btn-fg';
    Object.assign(fg.style, { position: 'relative', zIndex: '1', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '.4rem', width: '100%' });
    const lbl = document.createElement('span');
    lbl.className = 'bulk-btn-label';
    lbl.textContent = label;
    const pct = document.createElement('span');
    pct.className = 'bulk-btn-pct';
    if (showPercent) {
      pct.textContent = '0%';
      pct.style.visibility = 'visible';
    } else {
      pct.textContent = '';
      pct.style.visibility = 'hidden';
    }
    fg.append(lbl, pct);
    bulkBtn.append(bar, fg);
    bulkPctSpan = pct;
    bulkLabelSpan = lbl;
    if (indeterminate) {
      const shimmer = document.createElement('span');
      shimmer.className = 'bulk-btn-indeterminate';
      Object.assign(shimmer.style, { position: 'absolute', inset: '0', animation: 'indeterm 1.2s linear infinite', background: 'linear-gradient(90deg,transparent,rgba(255,255,255,.45),transparent)', zIndex: '0' });
      bulkBtn.prepend(shimmer);
    }
    return bar;
  }

  function updateBulkButton(label, pctValue) {
    if (bulkLabelSpan) {
      bulkLabelSpan.textContent = label;
    }
    if (bulkPctSpan) {
      if (pctValue === undefined || pctValue === null) {
        bulkPctSpan.style.visibility = 'hidden';
        bulkPctSpan.textContent = '';
      } else {
        bulkPctSpan.style.visibility = 'visible';
        bulkPctSpan.textContent = `${pctValue}%`;
      }
    }
  }

  function resetBulkButton() {
    bulkBtn.classList.remove('is-loading');
    bulkBtn.disabled = false;
    bulkBtn.innerHTML = 'Scan';
    bulkPctSpan = null;
    bulkLabelSpan = null;
  }

  function logBulkCancel(domains, tokens) {
    const payload = {};
    const doms = uniqueList(domains);
    const toks = uniqueList(tokens);
    if (doms.length) { payload.domains = doms; }
    if (toks.length) { payload.tokens = toks; }
    if (!payload.domains && !payload.tokens) { return; }
    payload.reason = 'client_cancel';
    fetch('/bulk/cancelled', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(() => { });
  }

  const MAX_DOMAINS = 500; // soft limit
  const MAX_FILE_KB = 200;  // warn threshold

  function updateProgress(done, total) {
    const pct = total ? Math.round((done / total) * 100) : 0;
    bulkProgress.style.width = pct + '%';
    bulkProgressText.textContent = pct + '%';
  }
  function addRow(idx, domain) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="padding:3px 6px;">${idx + 1}</td>` +
      `<td style="padding:3px 6px; font-weight:500;">${domain}</td>` +
      `<td style="padding:3px 6px;" data-field="status">queued</td>` +
      `<td style="padding:3px 6px;" data-field="engine">-</td>` +
      `<td style="padding:3px 6px;" data-field="count">-</td>` +
      `<td style="padding:3px 6px;" data-field="payload">-</td>` +
      `<td style="padding:3px 6px; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" data-field="techs"></td>` +
      `<td style="padding:3px 6px; color:#f87171;" data-field="error"></td>`;
    bulkTbody.appendChild(tr);
    return tr;
  }
  function rowUpdate(tr, data) {
    const statusCell = tr.querySelector('[data-field=status]');
    statusCell.textContent = data.status || 'ok';
    statusCell.style.color = (data.status && data.status !== 'ok') ? '#f87171' : '#10b981';
    tr.querySelector('[data-field=engine]').textContent = data.engine || '-';
    const techs = data.technologies || [];
    tr.querySelector('[data-field=count]').textContent = techs.length;
    const payloadCell = tr.querySelector('[data-field=payload]');
    const payloadBytes = data.payload_bytes;
    const payloadLabel = formatBytes(payloadBytes);
    payloadCell.textContent = payloadLabel || '-';
    payloadCell.title = payloadBytes != null ? `${payloadBytes} bytes` : '';
    const techPreview = techs.slice(0, 8).map(t => t.name + (t.version ? '(' + t.version + ')' : '')).join(', ');
    const techCell = tr.querySelector('[data-field=techs]');
    techCell.textContent = techPreview;
    techCell.title = techs.map(t => t.name + (t.version ? ' ' + t.version : '')).join(', ');
    const errorCell = tr.querySelector('[data-field=error]');
    if (data.error) {
      errorCell.textContent = data.error;
    } else {
      errorCell.textContent = '';
    }
  }

  // === Bulk State Persistence ===
  const BULK_STATE_KEY = 'techscan_bulk_state';

  function persistBulkState(jobId, domains, results, progress, status) {
    try {
      const state = {
        jobId,
        domains,
        results: results || [],
        progress: progress || 0,
        status: status || 'running',
        updatedAt: Date.now()
      };
      localStorage.setItem(BULK_STATE_KEY, JSON.stringify(state));
    } catch (e) { console.warn('Failed to persist bulk state:', e); }
  }

  function getBulkState() {
    try {
      const raw = localStorage.getItem(BULK_STATE_KEY);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (e) { return null; }
  }

  function clearBulkState() {
    try { localStorage.removeItem(BULK_STATE_KEY); } catch (e) { }
  }

  function restoreBulkTable(state) {
    if (!state || !state.domains) return;
    // Clear existing rows
    bulkTbody.innerHTML = '';
    queueResults.length = 0;

    // Restore domains
    state.domains.forEach((domain, idx) => {
      const tr = addRow(idx, domain);
      const result = (state.results || [])[idx];
      if (result) {
        rowUpdate(tr, result);
        queueResults.push({ domain, ...result });
      }
    });

    // Update progress
    const pct = state.progress || 0;
    if (bulkProgress) { bulkProgress.style.width = pct + '%'; }
    if (bulkProgressText) { bulkProgressText.textContent = pct + '%'; }

    // Update stats
    const completed = (state.results || []).filter(r => r && r.status).length;
    bulkStats.textContent = `Recovered: ${completed}/${state.domains.length} (${pct}%)`;

    // Make download visible if there are results
    const dlBtn = document.getElementById('bulk-download-bottom');
    if (dlBtn && queueResults.length > 0) {
      dlBtn.classList.remove('is-hidden');
    }
  }

  // Recovery callbacks for TechScanJobs
  window.showRecoveredJobProgress = function (jobData) {
    if (!jobData) return;
    const state = getBulkState();
    if (!state || state.jobId !== jobData.id) return;

    const pct = jobData.progress || 0;
    if (bulkProgress) { bulkProgress.style.width = pct + '%'; }
    if (bulkProgressText) { bulkProgressText.textContent = pct + '%'; }
    bulkStats.textContent = `Progress: ${jobData.completed || 0}/${jobData.total || state.domains.length} (${pct}%)`;

    // Update persisted state
    persistBulkState(state.jobId, state.domains, state.results, pct, 'running');
  };

  window.showRecoveredJobResult = async function (jobData) {
    if (!jobData) return;
    const state = getBulkState();

    // Handle bulk job completion
    if (jobData.results && Array.isArray(jobData.results)) {
      const domains = state ? state.domains : jobData.results.map(r => r.domain);
      // Restore table with final results
      bulkTbody.innerHTML = '';
      queueResults.length = 0;

      domains.forEach((domain, idx) => {
        const tr = addRow(idx, domain);
        const result = jobData.results[idx] || { domain, status: 'unknown' };
        rowUpdate(tr, result);
        queueResults.push({ domain, ...result });
      });

      if (bulkProgress) { bulkProgress.style.width = '100%'; }
      if (bulkProgressText) { bulkProgressText.textContent = '100%'; }
      bulkStats.textContent = `Completed: ${jobData.results.length} domains`;

      const dlBtn = document.getElementById('bulk-download-bottom');
      if (dlBtn && queueResults.length > 0) {
        dlBtn.classList.remove('is-hidden');
      }

      clearBulkState();
    } else if (jobData.result) {
      // Single job result - display in single scan area
      const data = typeof jobData.result === 'string' ? JSON.parse(jobData.result) : jobData.result;
      if (data && typeof renderSingleResult === 'function') {
        renderSingleResult(data);
      }
    }
  };

  // Check for pending bulk state on page load
  function checkBulkRecovery() {
    const state = getBulkState();
    if (!state) return;

    // Check if state is less than 1 hour old and not completed
    if (Date.now() - state.updatedAt > 3600000) {
      clearBulkState();
      return;
    }

    if (state.status === 'completed') {
      restoreBulkTable(state);
      clearBulkState();
      return;
    }

    // Restore table with current state
    restoreBulkTable(state);

    // If job exists, resume polling
    if (state.jobId && window.TechScanJobs) {
      bulkStats.textContent = 'Resuming scan...';
      window.TechScanJobs.startPolling(state.jobId, {
        onProgress: (data) => {
          window.showRecoveredJobProgress(data);
        },
        onComplete: (data) => {
          window.showRecoveredJobResult(data);
        },
        onError: (data, err) => {
          bulkStats.textContent = 'Error: ' + (err || 'Unknown error');
          clearBulkState();
        },
        onNotFound: () => {
          bulkStats.textContent = 'Job expired or completed';
          clearBulkState();
        }
      });
    }
  }

  // Run recovery check on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkBulkRecovery);
  } else {
    setTimeout(checkBulkRecovery, 200);
  }
  function buildCSV(results) {
    const header = ['domain', 'status', 'engine', 'tech_count', 'payload_bytes', 'technologies', 'error'];
    const lines = [header.join(',')];
    results.forEach(r => {
      const techList = (r.technologies || []).map(t => t.name + (t.version ? ' ' + t.version : ''));
      lines.push([
        r.domain,
        r.status || '',
        r.engine || '',
        (r.technologies || []).length,
        r.payload_bytes != null ? r.payload_bytes : '',
        '"' + techList.join('; ') + '"',
        '"' + (r.error || '') + '"'
      ].join(','));
    });
    return lines.join('\n');
  }

  bulkFile.addEventListener('change', async () => {
    const f = bulkFile.files && bulkFile.files[0];
    if (!f) { fileInfo.textContent = ''; return; }
    const kb = Math.round(f.size / 1024);
    fileInfo.textContent = `${f.name} (${kb} KB)` + (kb > MAX_FILE_KB ? ' ⚠ large file, processing might be slow' : '');
    const text = await f.text();
    const textarea = bulkForm.querySelector('textarea[name=domains]');
    const existing = textarea.value.trim();
    textarea.value = (existing ? existing + '\n' : '') + text.trim();
  });

  bulkForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    bulkError.style.display = 'none';
    queueAbort = false;
    const fd = new FormData(bulkForm);
    let domains = (fd.get('domains') || '').split(/\n+/).map(s => s.trim()).filter(Boolean);
    domains = Array.from(new Set(domains));
    if (!domains.length) { bulkError.textContent = 'No domains provided.'; bulkError.style.display = 'inline'; return; }
    if (domains.length > MAX_DOMAINS) { bulkError.textContent = `Too many domains (${domains.length}) > ${MAX_DOMAINS}. Reduce the list first.`; bulkError.style.display = 'inline'; return; }
    const sequential = true; // Always use sequential mode
    const fast_full = fd.get('fast_full') ? 1 : 0;
    bulkBtn.disabled = true; bulkCancel.classList.add('is-hidden');
    bulkDownloadBottom.classList.add('is-hidden');
    bulkTableWrapper.style.display = 'block';
    // Hide large track; we'll show progress inside the button instead
    progressWrapper.style.display = 'none';
    bulkTbody.innerHTML = '';
    updateProgress(0, domains.length);
    bulkStats.textContent = `Queued: ${domains.length}`;
    queueResults = [];
    currentBulkDomains = domains.slice();
    bulkProcessedCount = 0;
    currentBulkTokens = [];
    bulkRunToken = null;
    if (sequential) { bulkCancel.classList.remove('is-hidden'); }

    if (sequential) {
      bulkRunToken = createClientRequestToken('bulk');
      currentBulkTokens = domains.map((_, idx) => `${bulkRunToken}-${idx}`);
      // Sequential queue loop
      bulkBtn.classList.add('is-loading');
      bulkBtn.disabled = true;
      const progressBar = setupBulkButton('Scanning', { gradient: 'linear-gradient(90deg,#10b981,#4ade80)', showPercent: true });
      for (let i = 0; i < domains.length; i++) {
        if (queueAbort) { break; }
        const d = domains[i];
        const tr = addRow(i, d);
        tr.querySelector('[data-field=status]').textContent = 'scanning';
        const requestToken = currentBulkTokens[i] || `${createClientRequestToken('bulk')}-${i}`;
        currentBulkTokens[i] = requestToken;
        try {
          // Allow cancellation of the current fetch
          if (bulkController) { try { bulkController.abort(); } catch (_) { } }
          bulkController = new AbortController();
          const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: d, fast_full, client_request_id: requestToken, client_context: 'bulk-sequential' }),
            signal: bulkController.signal
          });
          const data = await res.json();
          if (!res.ok) { data.status = 'error'; data.error = data.error || ('HTTP ' + res.status); }
          rowUpdate(tr, data);
          queueResults.push({ domain: d, ...data });
          currentBulkTokens[i] = null;
        } catch (err) {
          if (err.name === 'AbortError') {
            rowUpdate(tr, { domain: d, status: 'canceled', technologies: [] });
            queueResults.push({ domain: d, status: 'canceled', technologies: [] });
            logBulkCancel([d], [requestToken]);
            currentBulkTokens[i] = null;
            bulkProcessedCount = i + 1;
            break;
          }
          rowUpdate(tr, { domain: d, status: 'error', error: err.message, technologies: [] });
          queueResults.push({ domain: d, status: 'error', error: err.message, technologies: [] });
          currentBulkTokens[i] = null;
        }
        bulkProcessedCount = i + 1;
        updateProgress(i + 1, domains.length);
        const pct = Math.round(((i + 1) / domains.length) * 100);
        if (progressBar) { progressBar.style.width = pct + '%'; }
        updateBulkButton('Scanning', pct);
        bulkStats.textContent = `Progress: ${i + 1}/${domains.length} (${pct}%)`;
      }
      // Done
      const barEnd = bulkBtn.querySelector('.btn-progress');
      if (barEnd) {
        barEnd.style.transition = 'width .18s ease-out';
        barEnd.style.width = '100%';
        setTimeout(() => { resetBulkButton(); }, 220);
      } else {
        resetBulkButton();
      }
      if (queueAbort) {
        const remaining = currentBulkDomains.slice(bulkProcessedCount);
        const remainingTokens = currentBulkTokens.slice(bulkProcessedCount).filter(Boolean);
        if (remaining.length || remainingTokens.length) { logBulkCancel(remaining, remainingTokens); }
      }
      currentBulkTokens = [];
      bulkRunToken = null;
    } else {
      // Parallel bulk endpoint - use async for background processing
      bulkProgress.style.width = '0%';
      bulkProgressInd.style.display = 'block';
      bulkBtn.classList.add('is-loading');
      bulkBtn.disabled = true;
      const bar = setupBulkButton('Processing', { gradient: 'linear-gradient(90deg,#10b981,#4ade80)', showPercent: false, indeterminate: true });
      try {
        if (bulkController) { try { bulkController.abort(); } catch (_) { } }
        bulkController = new AbortController();

        // Submit async bulk job
        const submitRes = await fetch('/bulk/async', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domains }),
          signal: bulkController.signal
        });
        const submitData = await submitRes.json();
        if (!submitRes.ok) { throw new Error(submitData.error || ('HTTP ' + submitRes.status)); }

        const jobId = submitData.job_id;
        if (!jobId) { throw new Error('No job_id returned'); }

        // Save to localStorage for recovery
        if (window.TechScanJobs) {
          window.TechScanJobs.addPendingJob(jobId, 'bulk', `${domains.length} domains`);
        }
        // Persist bulk state for table recovery
        persistBulkState(jobId, domains, [], 0, 'running');

        bulkStats.textContent = `Job submitted: ${domains.length} domains`;

        // Poll for job completion
        let completed = false;
        let pollCount = 0;
        const maxPolls = 600; // 10 minutes max for bulk

        while (!completed && pollCount < maxPolls) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          pollCount++;

          try {
            const statusRes = await fetch(`/api/job/${jobId}`, { signal: bulkController.signal });
            if (!statusRes.ok) { continue; }
            const jobStatus = await statusRes.json();

            // Update progress
            const pct = jobStatus.progress || 0;
            if (bulkProgress) { bulkProgress.style.width = pct + '%'; }
            bulkProgressInd.style.display = 'none';
            updateBulkButton('Processing', pct);
            bulkStats.textContent = `Progress: ${jobStatus.completed || 0}/${jobStatus.total || domains.length} (${pct}%)`;

            // Update persisted state during polling
            persistBulkState(jobId, domains, jobStatus.results || [], pct, 'running');

            if (jobStatus.status === 'completed') {
              completed = true;
              if (window.TechScanJobs) {
                window.TechScanJobs.removePendingJob(jobId);
              }
              // Clear bulk state since complete
              clearBulkState();
              // Show results in table
              const results = jobStatus.results || [];
              results.forEach((r, idx) => {
                const tr = addRow(idx, r.domain || domains[idx]);
                rowUpdate(tr, r || {});
                queueResults.push({ domain: r.domain || domains[idx], ...(r || {}) });
              });
              bulkProcessedCount = results.length;
            } else if (jobStatus.status === 'failed') {
              throw new Error(jobStatus.error || 'Bulk scan failed');
            }
          } catch (pollErr) {
            if (pollErr.name === 'AbortError') { throw pollErr; }
            console.warn('Bulk poll error:', pollErr);
          }
        }

        if (!completed) {
          bulkStats.textContent = 'Bulk scan running in background. Check Websites page for results.';
        } else {
          bulkStats.textContent = `Completed: ${bulkProcessedCount}/${domains.length}`;
        }

        // Done
        const bbar = bulkBtn.querySelector('.btn-progress');
        if (bbar) {
          bbar.style.transition = 'width .18s ease-out';
          bbar.style.width = '100%';
          setTimeout(() => { resetBulkButton(); }, 220);
        } else {
          resetBulkButton();
        }
      } catch (err) {
        if (err.name === 'AbortError') {
          bulkError.textContent = 'Cancelled';
          bulkError.style.display = 'inline';
          const remaining = currentBulkDomains.slice(bulkProcessedCount);
          if (remaining.length) { logBulkCancel(remaining); }
        } else {
          bulkError.textContent = 'Bulk error: ' + err.message;
          bulkError.style.display = 'inline';
        }
        resetBulkButton();
      }
    }
    // Error summary after run
    if (queueResults.length) {
      const buckets = { timeout: 0, dns: 0, ssl: 0, connection: 0, other: 0 };
      queueResults.forEach(r => {
        if (!r || r.status === 'ok') return;
        const err = (r.error || '').toLowerCase();
        if (/timeout|timed out|time out/.test(err)) buckets.timeout++;
        else if (/dns|nodename/.test(err)) buckets.dns++;
        else if (/ssl|cert/.test(err)) buckets.ssl++;
        else if (/connection|refused|unreachable/.test(err)) buckets.connection++;
        else buckets.other++;
      });
      bulkErrorSummary.style.display = 'block';
      bulkErrorSummary.textContent = `Error Summary => timeout:${buckets.timeout} dns:${buckets.dns} ssl:${buckets.ssl} connection:${buckets.connection} other:${buckets.other}`;
    }
    bulkBtn.disabled = false; bulkCancel.classList.add('is-hidden');
    if (queueResults.length) { bulkDownloadBottom.classList.remove('is-hidden'); }
  });

  bulkCancel.addEventListener('click', () => {
    queueAbort = true;
    bulkCancel.disabled = true;
    try { if (bulkController) bulkController.abort(); } catch (_) { }
    const remaining = currentBulkDomains.slice(bulkProcessedCount);
    const remainingTokens = currentBulkTokens.slice(bulkProcessedCount).filter(Boolean);
    if (remaining.length || remainingTokens.length) { logBulkCancel(remaining, remainingTokens); }
    currentBulkTokens = [];
    bulkRunToken = null;
  });
  function doDownload() {
    if (!queueResults.length) return;
    const csv = buildCSV(queueResults);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'bulk_results.csv'; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }
  bulkDownloadBottom.addEventListener('click', doDownload);

  window.handleTechIconError = function (img) {
    if (!img) return;
    const slug = img.dataset.slug || '';
    const currentIndex = parseInt(img.dataset.iconSourceIndex || '0', 10);
    if (slug) {
      const nextIndex = currentIndex + 1;
      if (nextIndex < ICON_BASES.length) {
        img.dataset.iconSourceIndex = String(nextIndex);
        img.src = `${ICON_BASES[nextIndex]}/${slug}.svg`;
        return;
      }
    }
    const fallback = img.getAttribute('data-fallback') || '•';
    const parent = img.parentElement;
    if (parent) {
      parent.textContent = fallback;
    }
  };

  // Handler for recovered job results - render to UI
  window.showRecoveredJobResult = async function (jobData) {
    if (!jobData) return;

    // Helper to format bytes
    function formatBytesSimple(bytes) {
      if (!bytes || bytes <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB'];
      let i = 0;
      while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
      return bytes.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    // Get domain from job
    const domains = jobData.domains || [];
    const domain = domains[0] || '';

    if (!domain) {
      console.warn('No domain in job data');
      return;
    }

    // Fetch full scan result from database
    try {
      const res = await fetch(`/domain?domain=${encodeURIComponent(domain)}`);
      if (!res.ok) {
        console.warn('Failed to fetch domain data');
        return;
      }
      const data = await res.json();

      // Update UI elements
      const statusLine = document.getElementById('status-line');
      const resultsBox = document.getElementById('results');
      const categoryGroups = document.getElementById('category-groups');
      const metaLine = document.getElementById('meta-line');
      const rawPre = document.getElementById('raw-json');

      if (statusLine) {
        statusLine.textContent = `Recovered scan completed for ${domain}`;
        statusLine.style.color = '#10b981';
      }

      if (resultsBox && categoryGroups) {
        const techs = data.technologies || [];
        const durationText = data.duration ? `${data.duration}s` : 'n/a';
        const payloadText = data.payload_bytes ? formatBytesSimple(data.payload_bytes) : 'n/a';

        // Set global variables for modal to work
        window._latestScan = data;
        window._latestTechs = techs;
        techs.forEach((t, i) => { t.__dashIdx = i; });

        // Update meta line
        if (metaLine) {
          metaLine.innerHTML = `<span>Domain: <strong>${data.domain || domain}</strong></span>` +
            `<span>Technologies: ${techs.length}</span>` +
            `<span>Duration: ${durationText}</span>` +
            `<span>Payload: ${payloadText}</span>`;
        }

        // Group by category - use global index for techCard
        if (techs.length && typeof getPrimaryCategory === 'function' && typeof techCard === 'function') {
          const groups = {};
          techs.forEach((t, globalIdx) => {
            const cat = getPrimaryCategory(t);
            const key = cat || 'Other';
            (groups[key] = groups[key] || []).push({ tech: t, idx: globalIdx });
          });
          const ordered = Object.keys(groups).sort();

          categoryGroups.innerHTML = ordered.map(cat => {
            const cards = groups[cat].map(item => techCard(item.tech, false, item.idx)).join('');
            return `<div class="category-group"><h4>${cat}</h4><div class="tech-grid">${cards}</div></div>`;
          }).join('');
        } else if (techs.length) {
          categoryGroups.innerHTML = `<div class="small-note">${techs.length} technologies detected</div>`;
        } else {
          categoryGroups.innerHTML = '<div class="small-note">(No technologies detected)</div>';
        }

        // Update raw JSON
        if (rawPre) {
          rawPre.textContent = JSON.stringify(data, null, 2);
        }

        // Show results box
        resultsBox.style.display = 'block';
        resultsBox.classList.add('fade-in');
      }
    } catch (err) {
      console.error('Error showing recovered job result:', err);
    }
  };

  // Handler for progress updates
  window.showRecoveredJobProgress = function (jobData) {
    if (!jobData) return;
    const statusLine = document.getElementById('status-line');
    if (statusLine) {
      const domain = (jobData.domains && jobData.domains[0]) || 'unknown';
      statusLine.textContent = `Background scan: ${domain} - ${jobData.progress || 0}%`;
      statusLine.style.color = '#3b82f6';
    }
  };




// ==========================================
// Job Recovery and Polling Logic
// ==========================================
  (function () {
    const JOB_STORAGE_KEY = 'techscan_pending_jobs';
    const POLL_INTERVAL = 2000; // 2 seconds
    let pollingIntervals = {};

    function getStoredJobs() {
      try {
        const stored = localStorage.getItem(JOB_STORAGE_KEY);
        return stored ? JSON.parse(stored) : {};
      } catch (e) { return {}; }
    }

    function saveStoredJobs(jobs) {
      try {
        localStorage.setItem(JOB_STORAGE_KEY, JSON.stringify(jobs));
      } catch (e) { console.warn('Failed to save jobs:', e); }
    }

    function addPendingJob(jobId, type, domain) {
      const jobs = getStoredJobs();
      jobs[jobId] = { type, domain, createdAt: Date.now() };
      saveStoredJobs(jobs);
    }

    function removePendingJob(jobId) {
      const jobs = getStoredJobs();
      delete jobs[jobId];
      saveStoredJobs(jobs);
    }

    async function pollJobStatus(jobId, callbacks) {
      try {
        const res = await fetch(`/api/job/${jobId}`);
        if (!res.ok) {
          if (res.status === 404) {
            removePendingJob(jobId);
            if (callbacks.onNotFound) callbacks.onNotFound(jobId);
            return null;
          }
          throw new Error(`HTTP ${res.status}`);
        }
        const job = await res.json();

        if (callbacks.onProgress) {
          callbacks.onProgress(job);
        }

        if (job.status === 'completed') {
          removePendingJob(jobId);
          if (callbacks.onComplete) callbacks.onComplete(job);
          return job;
        }

        if (job.status === 'failed') {
          removePendingJob(jobId);
          if (callbacks.onError) callbacks.onError(job, job.error);
          return job;
        }

        // Still running, continue polling
        return null;
      } catch (err) {
        console.warn('Poll error:', err);
        return null;
      }
    }

    function startPolling(jobId, callbacks) {
      if (pollingIntervals[jobId]) return;

      const poll = async () => {
        const result = await pollJobStatus(jobId, callbacks);
        if (result) {
          clearInterval(pollingIntervals[jobId]);
          delete pollingIntervals[jobId];
        }
      };

      poll(); // immediate first poll
      pollingIntervals[jobId] = setInterval(poll, POLL_INTERVAL);
    }

    function stopPolling(jobId) {
      if (pollingIntervals[jobId]) {
        clearInterval(pollingIntervals[jobId]);
        delete pollingIntervals[jobId];
      }
    }

    // Check for pending jobs on page load
    function checkPendingJobs() {
      const jobs = getStoredJobs();
      const pendingIds = Object.keys(jobs);

      if (pendingIds.length === 0) return;

      console.log('Found pending jobs:', pendingIds.length);

      pendingIds.forEach(jobId => {
        const job = jobs[jobId];
        // Only poll jobs less than 1 hour old
        if (Date.now() - job.createdAt > 3600000) {
          removePendingJob(jobId);
          return;
        }

        startPolling(jobId, {
          onProgress: (data) => {
            console.log(`Job ${jobId}: ${data.status} ${data.progress}%`);
            // Update UI with recovered job progress
            if (window.showRecoveredJobProgress) {
              window.showRecoveredJobProgress(data);
            }
          },
          onComplete: (data) => {
            console.log(`Job ${jobId} completed`);
            if (window.showRecoveredJobResult) {
              window.showRecoveredJobResult(data);
            } else {
              // Show notification
              const domain = job.domain || 'Domain';
              const msg = `Scan for ${domain} completed! Refresh to see results.`;
              if (typeof statusLine !== 'undefined' && statusLine) {
                statusLine.textContent = msg;
                statusLine.style.color = '#10b981';
              }
            }
          },
          onError: (data, error) => {
            console.log(`Job ${jobId} failed:`, error);
          },
          onNotFound: () => {
            console.log(`Job ${jobId} not found, removing`);
          }
        });
      });
    }

    // Expose for use by scan handlers
    window.TechScanJobs = {
      addPendingJob,
      removePendingJob,
      startPolling,
      stopPolling,
      getStoredJobs,
      checkPendingJobs
    };

    // Auto-check on load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', checkPendingJobs);
    } else {
      setTimeout(checkPendingJobs, 100);
    }
  })();
