/* Extracted from index.html */
async function postJSON(url, data) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  const txt = await r.text();
  let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
  if (!r.ok) throw new Error(j.error || 'Request failed');
  return j;
}

// Simple deterministic color map for tech icons (hash first char groups)
function iconColorFor(name) {
  const palette = ['#3b82f6', '#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#0ea5e9', '#ef4444', '#14b8a6', '#84cc16'];
  if (!name) return '#475569';
  let h = 0; for (let i = 0; i < name.length; i++) { h = (h * 31 + name.charCodeAt(i)) >>> 0; }
  return palette[h % palette.length];
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

const form = document.getElementById('single-form');
const domainInput = document.getElementById('domain');
const modeSelect = document.getElementById('mode');
const resDiv = document.getElementById('single-result');
const techGrid = document.getElementById('tech-grid');
const rawPre = document.getElementById('raw-json');
const catDiv = document.getElementById('categories');
const resDomain = document.getElementById('res-domain');
const errorBox = document.getElementById('single-error');
const scanBtnText = document.getElementById('scanBtnText');
const scanSpinner = document.getElementById('scanSpinner');
const diagPre = document.getElementById('diag-json');

// History elements
const historyForm = document.getElementById('history-form');
const historyDomain = document.getElementById('history-domain');
const historyLimit = document.getElementById('history-limit');
const historyErr = document.getElementById('history-error');
const historyWrap = document.getElementById('history-table-wrap');
const historyTbody = document.querySelector('#history-table tbody');
const historyRefreshBtn = document.getElementById('history-refresh');
const historyPrev = document.getElementById('history-prev');
const historyNext = document.getElementById('history-next');
const historyPageInfo = document.getElementById('history-page-info');
const historyPageJump = document.getElementById('history-page-jump');
const historyGo = document.getElementById('history-go');
let _lastHistory = { domain: null, limit: 10, total: 0 };
let _historyOffset = 0;

function disableNextHistory() {
  if (!_lastHistory.total) return false;
  const nextOffset = _historyOffset + _lastHistory.limit;
  return nextOffset >= _lastHistory.total;
}
function updateHistoryPageInfo() {
  const page = Math.floor(_historyOffset / _lastHistory.limit) + 1;
  const totalPages = _lastHistory.total ? Math.max(1, Math.ceil(_lastHistory.total / _lastHistory.limit)) : '?';
  historyPageJump.value = page;
  historyPageInfo.textContent = `Page ${page}/${totalPages} | Offset ${_historyOffset}${_lastHistory.total ? ' | Total ' + _lastHistory.total : ''}`;
  historyPrev.disabled = _historyOffset === 0;
  historyNext.disabled = disableNextHistory();
}
historyPrev.addEventListener('click', () => { if (!_lastHistory.domain) return; _historyOffset = Math.max(0, _historyOffset - _lastHistory.limit); historyRefreshBtn.click(); });
historyNext.addEventListener('click', () => { if (!_lastHistory.domain) return; if (disableNextHistory()) return; _historyOffset += _lastHistory.limit; historyRefreshBtn.click(); });
historyGo.addEventListener('click', () => { if (!_lastHistory.domain) return; const p = parseInt(historyPageJump.value); if (!p || p < 1) return; _historyOffset = (p - 1) * _lastHistory.limit; historyRefreshBtn.click(); });

// Search elements
const searchForm = document.getElementById('search-form');
const searchTech = document.getElementById('search-tech');
const searchVersion = document.getElementById('search-version');
const searchCategory = document.getElementById('search-category');
const searchLimit = document.getElementById('search-limit');
const searchNew24 = document.getElementById('search-new24');
const searchErr = document.getElementById('search-error');
const searchWrap = document.getElementById('search-table-wrap');
const searchTbody = document.querySelector('#search-table tbody');
const searchTable = document.getElementById('search-table');
const searchPrev = document.getElementById('search-prev');
const searchNext = document.getElementById('search-next');
const searchPageInfo = document.getElementById('search-page-info');
const searchPageJump = document.getElementById('search-page-jump');
const searchGo = document.getElementById('search-go');
let _searchData = [];
let _searchSort = { key: 'last_seen', dir: 'desc' };
let _searchOffset = 0;
let _searchQueryState = { tech: null, version: null, category: null, limit: 50, total: 0, new24: false };

function setLoading(state) {
  if (state) {
    scanBtnText.textContent = 'Scanning';
    scanSpinner.classList.remove('hidden');
  } else {
    scanBtnText.textContent = 'Scan';
    scanSpinner.classList.add('hidden');
  }
}

form.addEventListener('submit', async e => {
  e.preventDefault();
  const domain = domainInput.value.trim().toLowerCase();
  if (!domain) return;
  errorBox.classList.add('hidden');
  setLoading(true);
  try {
    const mode = modeSelect.value;
    const body = { domain };
    if (mode === 'quick') body.quick = 1;
    else if (mode === 'fast_full') body.fast_full = 1;
    else if (mode === 'deep') body.deep = 1;
    else if (mode === 'full') body.full = 1;
    // Quick mode: always request fresh to ensure enrichment/version evidence current
    if (mode === 'quick') body.fresh = 1;
    const data = await postJSON('/scan', body);
    renderSingle(domain, data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove('hidden');
  } finally { setLoading(false); }
});

function synthesizeCategories(data) {
  if (!data) return;
  if (data.categories && Object.keys(data.categories).length) return; // already present
  const cats = {};
  (data.technologies || []).forEach(t => {
    (t.categories || []).forEach(c => {
      cats[c] = cats[c] || [];
      if (!cats[c].some(x => x.name === t.name && x.version === t.version)) {
        cats[c].push({ name: t.name, version: t.version });
      }
    });
  });
  if (Object.keys(cats).length) {
    data.categories = cats;
  }
}

// CDN icon integration only (user request) with letter fallback.
const ICON_REMOTE_BASE = 'https://unpkg.com/tech-stack-icons@3.3.2/icons';
const REMOTE_ICON_MAP = {
  'wordpress': 'wordpress',
  'react': 'react',
  'vue.js': 'vue', 'vue': 'vue',
  'angular': 'angular',
  'laravel': 'laravel',
  'tailwind css': 'tailwindcss', 'tailwind': 'tailwindcss',
  'php': 'php',
  'mysql': 'mysql',
  'redis': 'redis',
  'nginx': 'nginx',
  'apache': 'apache',
  'cloudflare': 'cloudflare',
  'django': 'django',
  'flask': 'flask',
  'fastapi': 'fastapi',
  'symfony': 'symfony',
  'spring': 'springboot', 'spring boot': 'springboot',
  'magento': 'magento',
  'shopify': 'shopify',
  'prestashop': 'prestashop',
  'express': 'express',
  'drupal': 'drupal',
  'joomla': 'joomla',
  'woocommerce': 'woocommerce',
  'jquery': 'jquery',
  'npm': 'npm',
  'pnpm': 'pnpm',
  'yarn': 'yarn',
  'vite': 'vite',
  'svelte': 'svelte',
  'astro': 'astro',
  'gatsby': 'gatsby',
  'next.js': 'nextjs', 'nextjs': 'nextjs',
  'nuxt.js': 'nuxtjs', 'nuxtjs': 'nuxtjs'
};

const failCounts = {};
function fallbackIcon(img) {
  try {
    const name = img.dataset.tech || '?';
    const parent = img.parentElement;
    if (parent) {
      const letter = name.charAt(0).toUpperCase();
      const color = iconColorFor(name);
      parent.outerHTML = `<div class='tech-icon' style="background:${color}" title='${name}'>${letter}</div>`;
    }
  } catch (_e) { console.error(_e); }
}

let failedRemoteIcons = new Set(); // simple session-level only now
try {
  const storedFailed = localStorage.getItem('techscan_failed_remote_icons');
  if (storedFailed) {
    JSON.parse(storedFailed).forEach(k => failedRemoteIcons.add(k));
  }
} catch (_err) { /* ignore storage errors */ }
function techIconHTML(name, version) {
  if (!name) return null;
  let title = version ? `${name} ${version}` : name;

  // Normalize tech name to match local icon filename
  // Allow + and # for C++, C#
  let iconKey = name.toLowerCase().replace(/[^a-z0-9+#]/g, '');

  // Manual overrides for known mismatches
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
    'mariadb': 'mariadb',
    'elasticsearch': 'elastic',
    'tailwind': 'tailwindcss', 'tailwind css': 'tailwindcss'
  };

  if (iconMap[name.toLowerCase()]) {
    iconKey = iconMap[name.toLowerCase()];
  } else if (iconMap[iconKey]) {
    iconKey = iconMap[iconKey];
  }

  const localPath = `/static/icons/tech/${encodeURIComponent(iconKey)}.svg`;
  return `<div class='tech-logo'><img src='${localPath}' alt='${name} logo' title='${title}' data-tech='${name}' data-version='${version || ''}' onerror='fallbackIcon(this)'/></div>`;
}

// Rerender helpers when toggle changes
let _lastSingleData = null; let _lastSingleDomain = null;
let _lastDomainLookup = null; // {domain, data}
function reRenderAfterToggle() {
  if (_lastSingleData && _lastSingleDomain) {
    renderSingle(_lastSingleDomain, _lastSingleData);
  }
  if (_lastDomainLookup) {
    renderDomainLookup(_lastDomainLookup.domain, _lastDomainLookup.data);
  }
}
// Preload a few common icons (session only)
['wordpress', 'react', 'laravel', 'vue', 'angular', 'tailwindcss', 'php', 'mysql', 'redis'].forEach(k => {
  if (!REMOTE_ICON_MAP[k]) return; const img = new Image(); img.src = `${ICON_REMOTE_BASE}/${REMOTE_ICON_MAP[k]}.svg`;
});

function renderSingle(domain, data) {
  _lastSingleData = data; _lastSingleDomain = domain;
  synthesizeCategories(data); // ensure categories fallback if backend still empty
  resDiv.classList.remove('hidden');
  resDomain.textContent = domain + (data.cached ? ' (cached)' : '');
  techGrid.innerHTML = '';
  (data.technologies || []).forEach(t => {
    const el = document.createElement('div');
    el.className = 'tech has-icon';
    el.innerHTML = `<div class='tech-head'>${techIconHTML(t.name || '', t.version)}<div style='display:flex;flex-direction:column;gap:.3rem'><h3>${escapeHtml(t.name || '')}</h3>` +
      (t.version ? `<div class='version'>${escapeHtml(t.version)}</div>` : '') + `</div></div>` +
      `<div class='badge-row'>${(t.categories || []).map(c => `<span class='badge'>${escapeHtml(c)}</span>`).join('')}</div>`;
    techGrid.appendChild(el);
  });
  catDiv.innerHTML = '';
  const cats = data.categories || {};
  Object.keys(cats).sort().forEach(c => {
    const block = document.createElement('div');
    block.className = 'cat-block';
    block.innerHTML = `<h4>${escapeHtml(c)}</h4><div class='badge-row'>` +
      cats[c].map(x => `<span class='badge'>${escapeHtml(x.name)}${x.version ? ' ' + escapeHtml(x.version) : ''}</span>`).join('') + '</div>';
    catDiv.appendChild(block);
  });
  rawPre.textContent = JSON.stringify(data.raw || {}, null, 2);
}

async function fetchDiag(params) {
  const qs = Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const r = await fetch(`/admin/quick_diag?${qs}`);
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { throw new Error('Invalid JSON diag'); }
  if (!r.ok) { throw new Error(j.error || 'Diag failed'); }
  return j;
}

// Diagnostics buttons removed for simplified UI; keep function available if needed later.

function fmt(ts) {
  if (!ts && ts !== 0) return '-';
  try { return new Date(ts * 1000).toLocaleString(); } catch { return ts; }
}

historyForm.addEventListener('submit', async e => {
  e.preventDefault();
  const dom = historyDomain.value.trim().toLowerCase();
  if (!dom) return;
  historyErr.classList.add('hidden');
  historyWrap.classList.add('hidden');
  historyTbody.innerHTML = '';
  try {
    const limit = parseInt(historyLimit.value) || 10;
    _lastHistory = { domain: dom, limit, total: 0 };
    _historyOffset = 0;
    const r = await fetch(`/history?domain=${encodeURIComponent(dom)}&limit=${limit}&offset=${_historyOffset}`);
    const txt = await r.text();
    let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
    if (!r.ok) throw new Error(j.error || 'History failed');
    _lastHistory.total = j.total || 0;
    ; (j.history || []).forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${item.mode}</td>` +
        `<td>${fmt(item.started_at)}</td>` +
        `<td>${fmt(item.finished_at)}</td>` +
        `<td>${item.duration_ms}</td>` +
        `<td>${item.from_cache ? 'yes' : 'no'}</td>` +
        `<td>${item.retries}</td>` +
        `<td>${item.timeout_used}</td>`;
      historyTbody.appendChild(tr);
    });
    historyWrap.classList.remove('hidden');
    updateHistoryPageInfo();
    if (!(j.history || []).length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="7" style="color:var(--text-dim);font-style:italic">No history</td>';
      historyTbody.appendChild(tr);
    }
  } catch (err) {
    historyErr.textContent = err.message;
    historyErr.classList.remove('hidden');
  }
});

historyRefreshBtn.addEventListener('click', async () => {
  if (!_lastHistory.domain) {
    historyErr.textContent = 'Belum ada histori yang dimuat.';
    historyErr.classList.remove('hidden');
    return;
  }
  // trigger fetch with stored state
  historyErr.classList.add('hidden');
  historyWrap.classList.add('hidden');
  historyTbody.innerHTML = '';
  try {
    const r = await fetch(`/history?domain=${encodeURIComponent(_lastHistory.domain)}&limit=${_lastHistory.limit}&offset=${_historyOffset}`);
    const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
    if (!r.ok) throw new Error(j.error || 'History failed');
    ; (j.history || []).forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${item.mode}</td>` +
        `<td>${fmt(item.started_at)}</td>` +
        `<td>${fmt(item.finished_at)}</td>` +
        `<td>${item.duration_ms}</td>` +
        `<td>${item.from_cache ? 'yes' : 'no'}</td>` +
        `<td>${item.retries}</td>` +
        `<td>${item.timeout_used}</td>`;
      historyTbody.appendChild(tr);
    });
    historyWrap.classList.remove('hidden');
    if (j.total !== undefined) _lastHistory.total = j.total;
    updateHistoryPageInfo();
    if (!(j.history || []).length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="7" style="color:var(--text-dim);font-style:italic">No history</td>';
      historyTbody.appendChild(tr);
    }
  } catch (err) {
    historyErr.textContent = err.message;
    historyErr.classList.remove('hidden');
  }
});

searchForm.addEventListener('submit', async e => {
  e.preventDefault();
  const tech = searchTech.value.trim();
  if (!tech) return;
  searchErr.classList.add('hidden');
  searchWrap.classList.add('hidden');
  searchTbody.innerHTML = '';
  const params = new URLSearchParams();
  params.set('tech', tech);
  const ver = searchVersion.value.trim(); if (ver) params.set('version', ver);
  const cat = searchCategory.value.trim(); if (cat) params.set('category', cat);
  const lim = parseInt(searchLimit.value) || 50; params.set('limit', lim);
  if (searchNew24 && searchNew24.checked) params.set('new24', '1');
  try {
    _searchOffset = 0;
    _searchQueryState = { tech, version: ver || null, category: cat || null, limit: lim, total: 0, new24: (searchNew24 ? searchNew24.checked : false) };
    params.set('offset', _searchOffset);
    const r = await fetch(`/search?${params.toString()}`);
    const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
    if (!r.ok) throw new Error(j.error || 'Search failed');
    _searchData = j.results || []; _searchQueryState.total = j.total || 0;
    renderSearchTable();
    searchWrap.classList.remove('hidden');
    if (!(j.results || []).length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="6" style="color:var(--text-dim);font-style:italic">No results</td>';
      searchTbody.appendChild(tr);
    }
    updateSearchPageInfo();
  } catch (err) {
    searchErr.textContent = err.message;
    searchErr.classList.remove('hidden');
  }
});

function renderSearchTable() {
  searchTbody.innerHTML = '';
  _searchData.forEach(item => {
    const tr = document.createElement('tr');
    const isNew = (Date.now() / 1000 - item.first_seen) < 86400;
    if (isNew) tr.classList.add('new-domain');
    tr.innerHTML = `<td>${escapeHtml(item.domain)}${isNew ? '<span class="new-chip">NEW</span>' : ''}</td>` +
      `<td>${escapeHtml(item.tech_name)}</td>` +
      `<td>${escapeHtml(item.version || '')}</td>` +
      `<td>${(item.categories || []).map(c => escapeHtml(c)).join(', ')}</td>` +
      `<td>${fmt(item.first_seen)}</td>` +
      `<td>${fmt(item.last_seen)}</td>`;
    searchTbody.appendChild(tr);
  });
}

function sortSearch(key) {
  if (_searchSort.key === key) {
    _searchSort.dir = _searchSort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    _searchSort.key = key;
    _searchSort.dir = 'asc';
  }
  _searchOffset = 0;
  fetchSearchPage();
}

// Attach click handlers to headers
(function () {
  const headers = searchTable.querySelectorAll('thead th');
  const map = ['domain', 'tech_name', 'version', 'categories', 'first_seen', 'last_seen'];
  headers.forEach((th, i) => {
    th.style.cursor = 'pointer';
    th.addEventListener('click', () => {
      sortSearch(map[i]);
    });
  });
})();

function fetchSearchPage() {
  const params = new URLSearchParams();
  params.set('tech', _searchQueryState.tech);
  if (_searchQueryState.version) params.set('version', _searchQueryState.version);
  if (_searchQueryState.category) params.set('category', _searchQueryState.category);
  if (_searchQueryState.new24) params.set('new24', '1');
  params.set('limit', _searchQueryState.limit);
  if (_searchSort.key) { params.set('sort', _searchSort.key); params.set('dir', _searchSort.dir); }
  params.set('offset', _searchOffset);
  fetch(`/search?${params.toString()}`)
    .then(r => r.text().then(t => ({ ok: r.ok, text: t })))
    .then(({ ok, text }) => {
      let j; try { j = JSON.parse(text); } catch { throw new Error('Invalid JSON'); }
      if (!ok) throw new Error(j.error || 'Search failed');
      _searchData = j.results || []; if (j.total !== undefined) _searchQueryState.total = j.total;
      renderSearchTable();
      updateSearchPageInfo();
      if (!_searchData.length) {
        searchTbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-dim);font-style:italic">No results</td></tr>';
      }
    })
    .catch(e => {
      searchErr.textContent = e.message;
      searchErr.classList.remove('hidden');
    });
}
searchPrev.addEventListener('click', () => { if (!_searchQueryState.tech) return; _searchOffset = Math.max(0, _searchOffset - _searchQueryState.limit); fetchSearchPage(); });
searchNext.addEventListener('click', () => { if (!_searchQueryState.tech) return; if (disableNextSearch()) return; _searchOffset += _searchQueryState.limit; fetchSearchPage(); });
searchGo.addEventListener('click', () => { if (!_searchQueryState.tech) return; const p = parseInt(searchPageJump.value); if (!p || p < 1) return; _searchOffset = (p - 1) * _searchQueryState.limit; fetchSearchPage(); });
function disableNextSearch() {
  if (!_searchQueryState.total) return false;
  const nextOffset = _searchOffset + _searchQueryState.limit;
  return nextOffset >= _searchQueryState.total;
}
function updateSearchPageInfo() {
  const page = Math.floor(_searchOffset / _searchQueryState.limit) + 1;
  const totalPages = _searchQueryState.total ? Math.max(1, Math.ceil(_searchQueryState.total / _searchQueryState.limit)) : '?';
  searchPageJump.value = page;
  searchPageInfo.textContent = `Page ${page}/${totalPages} | Offset ${_searchOffset}${_searchQueryState.total ? ' | Total ' + _searchQueryState.total : ''}`;
  searchPrev.disabled = _searchOffset === 0;
  searchNext.disabled = disableNextSearch();
}
if (searchNew24) {
  searchNew24.addEventListener('change', () => { if (!_searchQueryState.tech) return; searchForm.dispatchEvent(new Event('submit')); });
}
function debounce(fn, wait) { let t; return function (...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), wait); }; }
const autoSearch = debounce(() => {
  if (!searchTech.value.trim()) return;
  if (!_searchQueryState.tech || searchTech.value.trim() !== _searchQueryState.tech) {
    searchForm.dispatchEvent(new Event('submit'));
  } else {
    _searchQueryState.version = searchVersion.value.trim() || null;
    _searchQueryState.category = searchCategory.value.trim() || null;
    _searchQueryState.new24 = searchNew24 ? searchNew24.checked : false;
    _searchOffset = 0;
    fetchSearchPage();
  }
}, 500);
[searchTech, searchVersion, searchCategory].forEach(el => el.addEventListener('input', autoSearch));

// Diff logic
const diffForm = document.getElementById('diff-form');
const diffDomain = document.getElementById('diff-domain');
const diffErr = document.getElementById('diff-error');
const diffResult = document.getElementById('diff-result');
const diffMeta = document.getElementById('diff-meta');
const diffAdded = document.getElementById('diff-added');
const diffRemoved = document.getElementById('diff-removed');
const diffChanged = document.getElementById('diff-changed');
diffForm.addEventListener('submit', async e => {
  e.preventDefault();
  diffErr.classList.add('hidden');
  diffResult.classList.add('hidden');
  diffAdded.innerHTML = diffRemoved.innerHTML = diffChanged.innerHTML = '';
  const dom = diffDomain.value.trim().toLowerCase(); if (!dom) return;
  try {
    const r = await fetch(`/diff?domain=${encodeURIComponent(dom)}`);
    const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
    if (!r.ok) throw new Error(j.error || 'Diff failed');
    diffMeta.textContent = `Latest: ${new Date(j.latest_scan * 1000).toLocaleString()} | Previous: ${new Date(j.previous_scan * 1000).toLocaleString()} | Added ${j.added.length} | Removed ${j.removed.length} | Changed ${j.changed_count} | Unchanged ${j.unchanged_count}`;
    (j.added || []).forEach(t => {
      const li = document.createElement('li');
      li.textContent = t.name + (t.version ? ' ' + t.version : '');
      diffAdded.appendChild(li);
    });
    (j.removed || []).forEach(t => {
      const li = document.createElement('li');
      li.textContent = t.name + (t.version ? ' ' + t.version : '');
      diffRemoved.appendChild(li);
    });
    (j.changed || []).forEach(c => {
      const li = document.createElement('li');
      let text = c.name;
      if (c.upgrade_path) {
        text += `: ${c.upgrade_path.from || '(none)'} -> ${c.upgrade_path.to || '(none)'} (${c.upgrade_path.direction})`;
      } else {
        if (c.previous_versions && c.current_versions) {
          text += `: [${c.previous_versions.join(',')}] -> [${c.current_versions.join(',')}]`;
        }
      }
      diffChanged.appendChild(li); li.textContent = text;
    });
    diffResult.classList.remove('hidden');
  } catch (err) {
    diffErr.textContent = err.message;
    diffErr.classList.remove('hidden');
  }
});
// persist limit preferences
(function () {
  const hlim = localStorage.getItem('techscan_history_limit'); if (hlim && !isNaN(parseInt(hlim))) historyLimit.value = hlim;
  const slim = localStorage.getItem('techscan_search_limit'); if (slim && !isNaN(parseInt(slim))) searchLimit.value = slim;
})();
historyLimit.addEventListener('change', () => localStorage.setItem('techscan_history_limit', historyLimit.value));
searchLimit.addEventListener('change', () => localStorage.setItem('techscan_search_limit', searchLimit.value));
function updateSortIndicators() {
  const headers = searchTable.querySelectorAll('thead th');
  const map = ['domain', 'tech_name', 'version', 'categories', 'first_seen', 'last_seen'];
  headers.forEach((th, i) => {
    const key = map[i];
    const base = th.textContent.replace(/\s*[▲▼]$/, '');
    th.textContent = base;
    if (_searchSort.key === key) { th.textContent = base + (_searchSort.dir === 'asc' ? ' ▲' : ' ▼'); }
  });
}

// Domain lookup panel
const domainForm = document.getElementById('domain-form');
const lookupDomain = document.getElementById('lookup-domain');
const domainError = document.getElementById('domain-error');
const domainResult = document.getElementById('domain-result');
const domainTitle = document.getElementById('domain-res-title');
const domainTechGrid = document.getElementById('domain-tech-grid');
const domainCatDiv = document.getElementById('domain-cat');
domainForm.addEventListener('submit', async e => {
  e.preventDefault();
  const dom = lookupDomain.value.trim().toLowerCase();
  if (!dom) return;
  domainError.classList.add('hidden');
  domainResult.classList.add('hidden');
  domainTechGrid.innerHTML = '';
  domainCatDiv.innerHTML = '';
  try {
    const r = await fetch(`/domain?domain=${encodeURIComponent(dom)}`);
    const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { throw new Error('Invalid JSON'); }
    if (!r.ok) throw new Error(j.error || 'Lookup failed');
    domainTitle.textContent = `${j.domain} (${j.count} tech)`;
    renderDomainLookup(j.domain, j);
    const cats = j.categories || {};
    Object.keys(cats).sort().forEach(c => {
      const block = document.createElement('div');
      block.className = 'cat-block';
      block.innerHTML = `<h4>${c}</h4><div class='badge-row'>` +
        cats[c].map(x => `<span class='badge'>${x.name}${x.version ? ' ' + x.version : ''}</span>`).join('') + '</div>';
      domainCatDiv.appendChild(block);
    });
    domainResult.classList.remove('hidden');
  } catch (err) {
    domainError.textContent = err.message;
    domainError.classList.remove('hidden');
  }
});

function renderDomainLookup(domain, data) {
  _lastDomainLookup = { domain, data };
  domainTechGrid.innerHTML = '';
  (data.technologies || []).forEach(t => {
    const el = document.createElement('div');
    el.className = 'tech has-icon';
    el.innerHTML = `<div class='tech-head'>${techIconHTML(t.name || '', t.version)}<div style='display:flex;flex-direction:column;gap:.3rem'><h3>${escapeHtml(t.name || '')}</h3>` + (t.version ? `<div class='version'>${escapeHtml(t.version)}</div>` : '') + `</div></div>` + `<div class='badge-row'>${(t.categories || []).map(c => `<span class='badge'>${escapeHtml(c)}</span>`).join('')}</div>`;
    domainTechGrid.appendChild(el);
  });
}

// Bulk upload
const fileInput = document.getElementById('fileInput');
const bulkStatus = document.getElementById('bulk-status');
const bulkWrapper = document.getElementById('bulk-table-wrapper');
const bulkTableBody = document.querySelector('#bulk-table tbody');

let _bulkDomains = [];
fileInput.addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  _bulkDomains = Array.from(new Set(text.split(/\r?\n/).map(l => l.trim().toLowerCase()).filter(Boolean)));
  if (!_bulkDomains.length) {
    bulkStatus.textContent = 'No valid domains found';
    bulkStatus.classList.remove('hidden');
    bulkWrapper.classList.add('hidden');
    return;
  }
  bulkStatus.classList.add('hidden');
  bulkWrapper.classList.remove('hidden');
  bulkTableBody.innerHTML = '';
  _bulkDomains.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${d}</td><td>ready</td><td>-</td><td>-</td>`;
    bulkTableBody.appendChild(tr);
  });
});

async function runBulkScan(downloadCsv = false) {
  if (!_bulkDomains.length) {
    bulkStatus.textContent = 'Upload list terlebih dahulu.';
    bulkStatus.classList.remove('hidden');
    return;
  }
  bulkStatus.classList.add('hidden');
  // mark queued
  Array.from(bulkTableBody.rows).forEach(r => r.cells[1].textContent = 'queued');
  // Use backend defaults (timeout, retries, concurrency). Minimal payload.
  const payload = { domains: _bulkDomains };
  try {
    if (downloadCsv) {
      // request CSV
      const resp = await fetch('/bulk?format=csv', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!resp.ok) {
        const txt = await resp.text();
        bulkStatus.textContent = 'Bulk CSV failed: ' + txt.slice(0, 120);
        bulkStatus.classList.remove('hidden');
        return;
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'bulk_scan.csv';
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      return;
    }
    const resp = await postJSON('/bulk', payload);
    resp.results.forEach((r, i) => {
      const row = bulkTableBody.rows[i];
      if (!row) return;
      if (r.status === 'ok') {
        const top = (r.technologies || [])[0];
        row.cells[1].textContent = 'ok';
        row.cells[2].textContent = r.technologies.length;
        row.cells[3].textContent = top ? top.name + (top.version ? ' ' + top.version : '') : '-';
      } else {
        row.cells[1].textContent = 'error';
        row.cells[2].textContent = '0';
        row.cells[3].textContent = r.error || '-';
      }
    });
  } catch (err) {
    bulkStatus.textContent = err.message;
    bulkStatus.classList.remove('hidden');
  }
}
document.getElementById('bulk-scan-btn').addEventListener('click', () => runBulkScan(false));
document.getElementById('bulk-download-csv').addEventListener('click', () => runBulkScan(true));
