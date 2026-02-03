/* Extracted from tech_search.html */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('tech-form');
  const tbody = document.getElementById('ts-tbody');
  const summary = document.getElementById('ts-summary');
  const loading = document.getElementById('ts-loading');
  const pagingBar = document.getElementById('paging-bar');
  const pageInfo = document.getElementById('page-info');
  const pageSizeSel = document.getElementById('page-size');
  const btnFirst = document.getElementById('page-first');
  const btnPrev = document.getElementById('page-prev');
  const btnNext = document.getElementById('page-next');
  const btnLast = document.getElementById('page-last');

  const DEFAULT_PAGE_SIZE = parseInt(pageSizeSel?.value || '20', 10) || 20;
  const DEFAULT_SORT_KEY = 'last_seen';
  const DEFAULT_SORT_DIR = 'desc';

  if (!form) { console.error('[TechSearch] form #tech-form tidak ditemukan'); return; }

  // Diagnostics / fallback apiFetch
  if (typeof window.apiFetch !== 'function') {
    console.warn('[TechSearch] apiFetch tidak ditemukan; memakai fallback fetch');
    window.apiFetch = async (url, opts = {}) => {
      const r = await fetch(url, opts); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json();
    };
  }

  let currentPage = 1;
  let pageSize = DEFAULT_PAGE_SIZE;
  let totalRows = 0;
  let sortKey = DEFAULT_SORT_KEY;
  let sortDir = DEFAULT_SORT_DIR;
  let isDefaultView = true;

  const HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', '\'': '&#39;' };
  function escapeHTML(val) {
    if (val === undefined || val === null) return '';
    return String(val).replace(/[&<>"']/g, ch => HTML_ESCAPE_MAP[ch] || ch);
  }
  function highlightWithTerm(source, term) {
    const original = source == null ? '' : String(source);
    const lowerTerm = (term || '').toLowerCase();
    if (!lowerTerm) {
      return escapeHTML(original);
    }
    const lowerSource = original.toLowerCase();
    const hit = lowerSource.indexOf(lowerTerm);
    if (hit === -1) {
      return escapeHTML(original);
    }
    const before = original.slice(0, hit);
    const match = original.slice(hit, hit + term.length);
    const after = original.slice(hit + term.length);
    return `${escapeHTML(before)}<strong>${escapeHTML(match)}</strong>${escapeHTML(after)}`;
  }

  function fmtTime(ts) {
    if (!ts) return '';
    try { const d = new Date(ts * 1000); return d.toLocaleDateString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit' }) + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }); } catch (_) { return '' }
  }

  function buildParams(extra = {}) {
    const fd = new FormData(form);
    const params = new URLSearchParams();
    const tech = (fd.get('tech') || '').trim();
    const category = (fd.get('category') || '').trim();
    const version = (fd.get('version') || '').trim();
    if (tech) params.set('tech', tech);
    if (category) params.set('category', category);
    if (version) params.set('version', version);
    params.set('limit', pageSize);
    params.set('offset', (currentPage - 1) * pageSize);
    if (sortKey) params.set('sort', sortKey);
    if (sortDir) params.set('dir', sortDir);
    Object.entries(extra).forEach(([k, v]) => { if (v !== undefined && v !== null) params.set(k, v); });
    return params;
  }

  function hasActiveFilters() {
    const fd = new FormData(form);
    return ['tech', 'category', 'version'].some(name => ((fd.get(name) || '').trim().length > 0));
  }

  function shouldUseDefaultView() {
    return !hasActiveFilters() && currentPage === 1 && sortKey === DEFAULT_SORT_KEY && sortDir === DEFAULT_SORT_DIR;
  }

  function isDefaultQueryState() {
    return !hasActiveFilters() && currentPage === 1 && pageSize === DEFAULT_PAGE_SIZE && sortKey === DEFAULT_SORT_KEY && sortDir === DEFAULT_SORT_DIR;
  }

  async function runSearch(options = {}) {
    const skipPersist = options.skipPersist === true;
    const forceDefault = options.forceDefault === true;
    isDefaultView = forceDefault ? true : shouldUseDefaultView();
    const loadingLabel = isDefaultView ? 'Loading latest technologies...' : 'Searching...';
    loading.style.display = 'flex';
    tbody.innerHTML = `<tr><td colspan="7" id="ts-empty">${loadingLabel}</td></tr>`;
    summary.textContent = loadingLabel;
    summary.dataset.mode = isDefaultView ? 'default' : '';
    const t0 = performance.now();
    try {
      const params = buildParams();
      const data = await apiFetch('/search?' + params.toString());
      totalRows = data.total || 0;
      const renderedCount = renderResults(data.results || [], data.offset || 0);
      updateSummary(renderedCount);
      updatePaging();
      if (skipPersist) {
        if (isDefaultQueryState()) {
          window.history.replaceState(null, '', window.location.pathname);
        }
      } else {
        persistQueryToURL();
      }
      console.info('[TechSearch] Search OK', { duration_ms: +(performance.now() - t0).toFixed(1), total: totalRows });
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="small" style="color:#d66;">Error: ${e.message}</td></tr>`;
      pagingBar.style.display = 'none';
      console.error('[TechSearch] Search failed', e);
    } finally {
      loading.style.display = 'none';
      // Close suggestions after search completes
      try { hideSuggest(); } catch (_) { }
    }
  }

  function renderResults(rows, offset) {
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" id="ts-empty"><div style='padding:.9rem 0;display:flex;flex-direction:column;align-items:center;gap:.4rem;'>
        <div style='font-size:.7rem;font-weight:600;letter-spacing:.5px;'>No results</div>
        <div style='font-size:.55rem;opacity:.65;'>Change keywords or filters to try again.</div>
      </div></td></tr>`;
      return 0;
    }
    tbody.innerHTML = rows.map((r, i) => {
      const idx = offset + i + 1;
      const cat = (r.categories || []).join(', ');
      const versions = Array.isArray(r.versions) && r.versions.length
        ? r.versions.join(', ')
        : (r.version || '');
      return `<tr>
        <td class='mono' style='text-align:right;opacity:.7;'>${idx}</td>
        <td class='mono' style='word-break:break-all;'>${r.domain}</td>
        <td>${r.tech_name || ''}</td>
        <td class='nowrap'>${versions || ''}</td>
        <td>${cat || '<span style="opacity:.4">-</span>'}</td>
        <td class='nowrap'>${fmtTime(r.first_seen)}</td>
        <td class='nowrap'>${fmtTime(r.last_seen)}</td>
      </tr>`;
    }).join('');
    return rows.length;
  }

  // Small UI helper functions (prevent runtime errors if shared helpers are absent)
  function updateSummary(renderedCount) {
    try {
      if (isDefaultView) {
        const count = renderedCount || 0;
        summary.textContent = count ? `Showing latest ${count} technologies` : 'Showing latest technologies';
        summary.dataset.mode = 'default';
      } else {
        summary.textContent = totalRows ? (totalRows + ' results') : '';
        summary.dataset.mode = '';
      }
    } catch (_) { }
  }

  function updatePaging() {
    try {
      const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
      pageInfo.textContent = `Page ${currentPage}/${totalPages}`;
      pagingBar.style.display = totalRows > 0 ? 'flex' : 'none';
      btnPrev.disabled = currentPage <= 1; btnFirst.disabled = currentPage <= 1;
      btnNext.disabled = currentPage >= totalPages; btnLast.disabled = currentPage >= totalPages;
    } catch (_) { }
  }

  function persistQueryToURL() {
    try {
      if (isDefaultQueryState()) {
        window.history.replaceState(null, '', window.location.pathname);
        return;
      }
      const qp = buildParams();
      const newUrl = window.location.pathname + '?' + qp.toString();
      window.history.replaceState(null, '', newUrl);
    } catch (_) { }
  }

  function syncSortIndicators() {
    try {
      document.querySelectorAll('#ts-table thead th.sortable').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (th.dataset.sort === sortKey) {
          th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
        }
      });
    } catch (_) { }
  }

  function restoreFromURL() {
    try {
      const params = new URLSearchParams(window.location.search);
      const t = params.get('tech'); const c = params.get('category'); const v = params.get('version');
      if (t) document.getElementById('ts-tech').value = t;
      if (c) document.getElementById('ts-category').value = c;
      if (v) document.getElementById('ts-version').value = v;
      const p = parseInt(params.get('limit') || '', 10);
      if (p) { pageSize = p; pageSizeSel.value = String(p); }
      const off = parseInt(params.get('offset') || '', 10);
      if (!isNaN(off) && pageSize) { currentPage = Math.floor(off / pageSize) + 1; }
      const sortParam = params.get('sort');
      if (sortParam) { sortKey = sortParam; }
      const dirParam = params.get('dir');
      if (dirParam === 'asc' || dirParam === 'desc') { sortDir = dirParam; }
      syncSortIndicators();
      const trackedKeys = ['tech', 'category', 'version', 'limit', 'offset', 'sort', 'dir'];
      const hasTrackedParam = trackedKeys.some(key => params.has(key));
      if (hasTrackedParam) {
        runSearch();
      } else {
        runSearch({ skipPersist: true, forceDefault: true });
      }
    } catch (_) { }
  }

  // Debounce auto-search (450ms) & suggestions debounce (1000ms) with min length 2 (now for tech & category)
  const techInput = document.getElementById('ts-tech');
  const catInput = document.getElementById('ts-category');
  const verInput = document.getElementById('ts-version');
  const suggestBox = document.getElementById('ts-suggest');
  const suggestItemsEl = suggestBox?.querySelector('.sg-items');
  const suggestStatusEl = suggestBox?.querySelector('.sg-status');
  // Category suggestion elements
  const catSuggestBox = document.getElementById('cat-suggest');
  const catItemsEl = catSuggestBox?.querySelector('.cat-items');
  const catStatusEl = catSuggestBox?.querySelector('.cat-status');
  let searchDebounce = null;
  let suggestDebounce = null;
  let catSuggestDebounce = null;
  const SUGGEST_DELAY = 1000; // updated to 1s per request
  const SUGGEST_MIN = 2;
  let activeIndex = -1; // keyboard navigation
  let currentSuggestions = [];
  const suggestCache = {}; // prefix -> array
  const catSuggestCache = {}; // prefix -> categories array
  let lastTechSuggestQuery = '';
  let lastCatSuggestQuery = '';
  function scheduleSearch() {
    currentPage = 1;
    if (searchDebounce) clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => runSearch(), 450);
  }
  function scheduleSuggest() {
    if (!techInput) return;
    const val = techInput.value.trim();
    if (suggestDebounce) clearTimeout(suggestDebounce);
    if (!val || val.length < SUGGEST_MIN) { hideSuggest(); return; }
    showSuggestStatus('Loading...');
    suggestDebounce = setTimeout(() => fetchSuggestions(val), SUGGEST_DELAY);
  }
  function scheduleCatSuggest() {
    if (!catInput) return;
    const val = catInput.value.trim();
    if (catSuggestDebounce) clearTimeout(catSuggestDebounce);
    if (!val || val.length < SUGGEST_MIN) { hideCatSuggest(); return; }
    showCatStatus('Loading...');
    catSuggestDebounce = setTimeout(() => fetchCatSuggestions(val), SUGGEST_DELAY);
  }
  [techInput, catInput, verInput].filter(Boolean).forEach(inp => {
    inp.addEventListener('input', (e) => {
      scheduleSearch();
      if (e.target === techInput) scheduleSuggest();
      if (e.target === catInput) scheduleCatSuggest();
    });
  });

  function hideSuggest() {
    if (!suggestBox) return;
    suggestBox.style.display = 'none';
    if (suggestItemsEl) suggestItemsEl.innerHTML = '';
    if (suggestStatusEl) suggestStatusEl.style.display = 'none';
    activeIndex = -1; currentSuggestions = [];
  }
  function hideCatSuggest() {
    if (!catSuggestBox) return;
    catSuggestBox.style.display = 'none';
    if (catItemsEl) catItemsEl.innerHTML = '';
    if (catStatusEl) catStatusEl.style.display = 'none';
  }
  function showSuggestStatus(text) {
    if (!suggestBox || !suggestStatusEl) return;
    suggestStatusEl.textContent = text;
    suggestStatusEl.style.display = 'block';
    suggestBox.style.display = 'block';
  }
  function showCatStatus(text) {
    if (!catSuggestBox || !catStatusEl) return;
    catStatusEl.textContent = text;
    catStatusEl.style.display = 'block';
    catSuggestBox.style.display = 'block';
  }
  function showSuggestItems() {
    if (!suggestBox || !suggestItemsEl) return;
    suggestStatusEl && (suggestStatusEl.style.display = 'none');
    suggestBox.style.display = 'block';
  }
  function showCatItems() {
    if (!catSuggestBox || !catItemsEl) return;
    catStatusEl && (catStatusEl.style.display = 'none');
    catSuggestBox.style.display = 'block';
  }

  async function fetchSuggestions(prefix) {
    if (!suggestBox || !suggestItemsEl) return;
    const query = prefix.trim();
    if (!query) {
      hideSuggest();
      return;
    }
    lastTechSuggestQuery = query;
    const cacheKey = query.toLowerCase();
    if (Array.isArray(suggestCache[cacheKey])) {
      renderSuggestList(query, suggestCache[cacheKey]);
      return;
    }
    showSuggestStatus('Loading...');
    try {
      const params = new URLSearchParams({ prefix: query, limit: '12' });
      const data = await apiFetch('/tech_suggest?' + params.toString());
      if (lastTechSuggestQuery !== query) {
        return; // stale response
      }
      const list = Array.isArray(data?.suggestions) ? data.suggestions.filter(Boolean) : [];
      suggestCache[cacheKey] = list;
      renderSuggestList(query, list);
    } catch (err) {
      if (lastTechSuggestQuery !== query) {
        return;
      }
      console.warn('[TechSearch] gagal memuat saran teknologi', err);
      showSuggestStatus('Tidak bisa memuat saran');
    }
  }

  function renderSuggestList(prefix, list) {
    if (!suggestItemsEl) return;
    const entries = Array.isArray(list) ? list.map(v => (v == null ? '' : String(v))).filter(Boolean) : [];
    currentSuggestions = entries;
    activeIndex = -1;
    if (!entries.length) {
      suggestItemsEl.innerHTML = '';
      showSuggestStatus('Tidak ada saran');
      return;
    }
    const html = entries.map((name, i) => {
      const label = highlightWithTerm(name, prefix);
      return `<div class='sg-item' data-idx='${i}' data-val="${escapeHTML(name)}" style='padding:6px 8px;font-size:.6rem;cursor:pointer;display:flex;align-items:center;gap:.4rem;'>${label}</div>`;
    }).join('');
    suggestItemsEl.innerHTML = html;
    showSuggestItems();
    suggestBox.querySelectorAll('.sg-item').forEach(div => {
      div.addEventListener('mouseenter', () => setActive(parseInt(div.dataset.idx, 10)));
      div.addEventListener('click', () => selectActive(parseInt(div.dataset.idx, 10)));
    });
  }

  async function fetchCatSuggestions(prefix) {
    if (!catSuggestBox || !catItemsEl) return;
    const query = prefix.trim();
    if (!query) {
      hideCatSuggest();
      return;
    }
    lastCatSuggestQuery = query;
    const cacheKey = query.toLowerCase();
    if (Array.isArray(catSuggestCache[cacheKey])) {
      renderCatSuggestionList(query, catSuggestCache[cacheKey]);
      return;
    }
    showCatStatus('Loading...');
    try {
      const params = new URLSearchParams({ prefix: query, limit: '12' });
      const data = await apiFetch('/category_suggest?' + params.toString());
      if (lastCatSuggestQuery !== query) {
        return;
      }
      const list = Array.isArray(data?.suggestions) ? data.suggestions.filter(Boolean) : [];
      catSuggestCache[cacheKey] = list;
      renderCatSuggestionList(query, list);
    } catch (err) {
      if (lastCatSuggestQuery !== query) {
        return;
      }
      console.warn('[TechSearch] gagal memuat saran kategori', err);
      showCatStatus('Tidak bisa memuat saran');
    }
  }

  function renderCatSuggestionList(prefix, list) {
    if (!catItemsEl) { return; }
    const entries = Array.isArray(list) ? list.map(v => (v == null ? '' : String(v))).filter(Boolean) : [];
    if (!entries.length) {
      catItemsEl.innerHTML = '';
      showCatStatus('Tidak ada saran');
      return;
    }
    const html = entries.map((c, i) => {
      const label = highlightWithTerm(c, prefix);
      return `<div class='cat-item' data-idx='${i}' data-val="${escapeHTML(c)}" style='padding:6px 8px;font-size:.6rem;cursor:pointer;'>${label}</div>`;
    }).join('');
    catItemsEl.innerHTML = html;
    showCatItems();
    catSuggestBox.querySelectorAll('.cat-item').forEach(div => {
      div.addEventListener('click', () => {
        catInput.value = div.getAttribute('data-val');
        hideCatSuggest();
        currentPage = 1; runSearch();
      });
    });
  }

  function setActive(idx) {
    if (!suggestItemsEl) return;
    activeIndex = idx;
    suggestItemsEl.querySelectorAll('.sg-item').forEach(el => el.style.background = '');
    const el = suggestItemsEl.querySelector(`.sg-item[data-idx='${idx}']`);
    if (el) el.style.background = '#20303b';
  }
  function moveActive(delta) {
    if (!currentSuggestions.length) { return; }
    if (activeIndex === -1) { activeIndex = delta > 0 ? 0 : currentSuggestions.length - 1; }
    else { activeIndex = (activeIndex + delta + currentSuggestions.length) % currentSuggestions.length; }
    setActive(activeIndex);
  }
  function selectActive(idxOverride) {
    const idx = typeof idxOverride === 'number' ? idxOverride : activeIndex;
    if (idx < 0 || idx >= currentSuggestions.length) return;
    const val = currentSuggestions[idx];
    techInput.value = val;
    hideSuggest();
    currentPage = 1; runSearch();
  }

  // Hide suggestions on outside click / escape
  document.addEventListener('click', (e) => {
    if (!suggestBox || !techInput) return;
    if (suggestBox.contains(e.target) || e.target === techInput) return;
    hideSuggest();
  });
  document.addEventListener('click', (e) => {
    if (!catSuggestBox || !catInput) return;
    if (catSuggestBox.contains(e.target) || e.target === catInput) return;
    hideCatSuggest();
  });
  techInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { hideSuggest(); return; }
    if (e.key === 'ArrowDown') { moveActive(1); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { moveActive(-1); e.preventDefault(); }
    else if (e.key === 'Enter' && suggestBox && suggestBox.style.display !== 'none' && activeIndex >= 0) {
      e.preventDefault(); selectActive(activeIndex);
    }
  });
  catInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { hideCatSuggest(); return; }
    if (e.key === 'Enter' && catSuggestBox && catSuggestBox.style.display !== 'none') {
      const first = catItemsEl?.querySelector('.cat-item[data-idx="0"]');
      if (first) {
        catInput.value = first.getAttribute('data-val');
        hideCatSuggest(); currentPage = 1; runSearch(); e.preventDefault();
      }
    }
  });

  // If user manually clicks Search, cancel pending debounce to avoid duplicate
  document.getElementById('ts-submit')?.addEventListener('click', () => {
    if (searchDebounce) { clearTimeout(searchDebounce); searchDebounce = null; }
  });
  pageSizeSel?.addEventListener('change', () => {
    const newSize = parseInt(pageSizeSel.value, 10) || pageSize;
    if (newSize !== pageSize) {
      pageSize = newSize;
      currentPage = 1;
      runSearch();
    }
  });
  btnPrev?.addEventListener('click', () => { if (currentPage > 1) { currentPage--; runSearch(); } });
  btnNext?.addEventListener('click', () => { currentPage++; runSearch(); });
  btnFirst?.addEventListener('click', () => { if (currentPage !== 1) { currentPage = 1; runSearch(); } });
  btnLast?.addEventListener('click', () => { const tp = Math.max(1, Math.ceil(totalRows / pageSize)); if (currentPage !== tp) { currentPage = tp; runSearch(); } });

  document.querySelectorAll('#ts-table thead th.sortable').forEach(th => {
    th.style.cursor = 'pointer';
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (sortKey === k) { sortDir = (sortDir === 'asc' ? 'desc' : 'asc'); }
      else { sortKey = k; sortDir = 'asc'; }
      currentPage = 1; runSearch();
      syncSortIndicators();
    });
  });

  restoreFromURL();
  document.getElementById('ts-tech')?.focus();
});
