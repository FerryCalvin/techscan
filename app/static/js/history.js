// History page logic extracted from history.html
// Includes XSS protection via escapeHtml

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

document.addEventListener('DOMContentLoaded', () => {
    console.log('[history] script loaded, DOMContentLoaded');
    const form = document.getElementById('hist-form');
    const tbody = document.getElementById('hist-tbody');
    const loading = document.getElementById('hist-loading');
    const summary = document.getElementById('hist-summary');
    const pageInfo = document.getElementById('hist-page-info');
    const pageSizeSel = document.getElementById('hist-page-size');
    const pagingBar = document.getElementById('paging-bar');
    const btnFirst = document.getElementById('hist-first');
    const btnPrev = document.getElementById('hist-prev');
    const btnNext = document.getElementById('hist-next');
    const btnLast = document.getElementById('hist-last');
    // Removed dropdown sorting controls; use header click only
    const domainInput = document.getElementById('hist-domain');

    const domSuggestBox = document.getElementById('hist-domain-suggest');
    const domItemsEl = domSuggestBox?.querySelector('.hd-items');
    const domStatusEl = domSuggestBox?.querySelector('.hd-status');
    const DOM_SUGGEST_DELAY = 1000; const DOM_SUGGEST_MIN = 2; let domSuggestDebounce = null; const domCache = {}; let domActiveIndex = -1; let domCurrent = [];
    function hideDomSuggest() { if (!domSuggestBox) return; domSuggestBox.style.display = 'none'; if (domItemsEl) domItemsEl.innerHTML = ''; if (domStatusEl) domStatusEl.style.display = 'none'; domActiveIndex = -1; domCurrent = []; }
    function showDomStatus(text) { if (!domSuggestBox || !domStatusEl) return; domStatusEl.textContent = text; domStatusEl.style.display = 'block'; domSuggestBox.style.display = 'block'; }
    function showDomItems() { if (!domSuggestBox || !domItemsEl) return; domStatusEl && (domStatusEl.style.display = 'none'); domSuggestBox.style.display = 'block'; }
    function scheduleDomSuggest() { if (!domainInput) return; const val = domainInput.value.trim(); if (domSuggestDebounce) clearTimeout(domSuggestDebounce); if (!val || val.length < DOM_SUGGEST_MIN) { hideDomSuggest(); return; } showDomStatus('Loading...'); domSuggestDebounce = setTimeout(() => fetchDomainSuggest(val), DOM_SUGGEST_DELAY); }
    async function fetchDomainSuggest(prefix) {
        if (domCache[prefix]) { renderDomainSuggest(prefix, domCache[prefix]); return; }
        try {
            const resp = await apiFetch('/domain_suggest?prefix=' + encodeURIComponent(prefix));
            const list = resp.suggestions || [];
            domCache[prefix] = list;
            if (!list.length) { hideDomSuggest(); return; }
            renderDomainSuggest(prefix, list);
        } catch (e) { hideDomSuggest(); }
    }

    function renderDomainSuggest(prefix, list) {
        if (!domItemsEl) return;
        domCurrent = list || [];
        const pre = prefix.toLowerCase();
        const html = list.map((d, i) => {
            const low = d.toLowerCase();
            let label = escapeHtml(d);
            if (low.startsWith(pre)) {
                label = `<strong>${escapeHtml(d.slice(0, prefix.length))}</strong>${escapeHtml(d.slice(prefix.length))}`;
            }
            return `<div class='hd-item' data-idx='${i}' data-val="${escapeHtml(d)}" style='padding:6px 8px;cursor:pointer;'>${label}</div>`;
        }).join('');
        domItemsEl.innerHTML = html;
        showDomItems();
        domItemsEl.querySelectorAll('.hd-item').forEach(div => { div.addEventListener('mouseenter', () => setDomActive(parseInt(div.dataset.idx, 10))); div.addEventListener('click', () => selectDom(parseInt(div.dataset.idx, 10))); });
    }
    function setDomActive(idx) { if (!domItemsEl) return; domActiveIndex = idx; domItemsEl.querySelectorAll('.hd-item').forEach(el => el.style.background = ''); const el = domItemsEl.querySelector(`.hd-item[data-idx='${idx}']`); if (el) el.style.background = '#20303b'; }
    function moveDomActive(delta) { if (!domCurrent.length) return; if (domActiveIndex === -1) { domActiveIndex = delta > 0 ? 0 : domCurrent.length - 1; } else { domActiveIndex = (domActiveIndex + delta + domCurrent.length) % domCurrent.length; } setDomActive(domActiveIndex); }
    function selectDom(idxOverride) { const idx = typeof idxOverride === 'number' ? idxOverride : domActiveIndex; if (idx < 0 || idx >= domCurrent.length) return; const v = domCurrent[idx]; domainInput.value = v; hideDomSuggest(); currentPage = 1; loadHistory(); }
    domainInput?.addEventListener('input', () => { scheduleDomSuggest(); });
    document.addEventListener('click', (e) => { if (!domSuggestBox || !domainInput) return; if (domSuggestBox.contains(e.target) || e.target === domainInput) return; hideDomSuggest(); });
    domainInput?.addEventListener('keydown', (e) => { if (e.key === 'Escape') { hideDomSuggest(); return; } if (e.key === 'ArrowDown') { moveDomActive(1); e.preventDefault(); } else if (e.key === 'ArrowUp') { moveDomActive(-1); e.preventDefault(); } else if (e.key === 'Enter' && domSuggestBox && domSuggestBox.style.display !== 'none' && domActiveIndex >= 0) { e.preventDefault(); selectDom(domActiveIndex); } });
    let currentPage = 1; let pageSize = parseInt(pageSizeSel.value, 10); let totalRows = 0; let sortKey = 'finished_at'; let sortDir = 'desc';

    if (typeof window.apiFetch !== 'function') {
        window.apiFetch = async (url, opts = {}) => { const r = await fetch(url, opts); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); };
    }

    function fmtTime(ts) {
        const ms = normaliseTimestamp(ts);
        if (ms === null) return '';
        try {
            return new Date(ms).toLocaleString();
        } catch (_) {
            return '';
        }
    }

    function normaliseTimestamp(value) {
        const num = Number(value);
        if (!Number.isFinite(num)) {
            return null;
        }
        if (num > 1e12) {
            return Math.round(num);
        }
        if (num > 1e9) {
            return Math.round(num * 1000);
        }
        if (num > 1e6) {
            return Math.round(num);
        }
        if (num <= 0) {
            return 0;
        }
        return Math.round(num * 1000);
    }

    function fmtDuration(ms) {
        const value = Number(ms);
        if (!Number.isFinite(value) || value < 0) return '';
        if (value < 1000) return `${Math.round(value)} ms`;
        const seconds = value / 1000;
        if (seconds < 10) return `${seconds.toFixed(2)} s`;
        if (seconds < 60) return `${seconds.toFixed(1)} s`;
        const minutes = Math.floor(seconds / 60);
        const rem = seconds - minutes * 60;
        const remStr = rem >= 10 ? Math.round(rem).toString() : rem.toFixed(1);
        return `${minutes}m ${remStr}s`;
    }

    function fmtBytes(bytes) {
        if (bytes == null) return '';
        let value = Number(bytes);
        if (!Number.isFinite(value) || value < 0) return '';
        if (value === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let unitIndex = 0;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex += 1;
        }
        const precision = value >= 10 ? 1 : 2;
        return `${value.toFixed(precision)} ${units[unitIndex]}`;
    }

    function buildParams() {
        const params = new URLSearchParams();
        const dom = domainInput.value.trim();
        if (dom) params.set('domain', dom);
        params.set('limit', pageSize);
        params.set('offset', (currentPage - 1) * pageSize);
        params.set('sort', sortKey);
        params.set('dir', sortDir);
        return params;
    }

    async function loadHistory() {
        console.log('[history] loadHistory start', { page: currentPage, pageSize: pageSize, sort: sortKey, dir: sortDir });
        loading.style.display = 'flex';
        tbody.innerHTML = `<tr><td colspan="8" id="hist-empty">Loading...</td></tr>`;
        try {
            const params = buildParams();
            const dom = (domainInput && domainInput.value && domainInput.value.trim()) || '';
            let resp = null;
            // Prefer domain-specific history endpoint if domain provided
            if (dom) {
                try {
                    console.debug('Fetching domain history for', dom);
                    resp = await apiFetch(`/api/domain/${encodeURIComponent(dom)}/history?` + params.toString());
                    console.debug('[history] domain-specific response received', resp && (resp.scans || resp.history || resp.results || resp));
                } catch (e) {
                    // If domain-specific fails (maybe not available), fall back to /scan_history?domain=...
                    console.warn('Domain history fetch failed, falling back to /scan_history:', e);
                    resp = await apiFetch('/scan_history?' + params.toString());
                }
            } else {
                resp = await apiFetch('/scan_history?' + params.toString());
                console.debug('[history] scan_history response received', resp && (resp.results || resp));
            }

            // Normalise rows & total from either endpoint shapes
            const rows = resp.results || resp.history || resp.scans || resp || [];
            // total may be in resp.total or resp.count
            if (typeof resp.total === 'number') totalRows = resp.total;
            else if (typeof resp.count === 'number') totalRows = resp.count;
            else totalRows = rows.length;

            // render rows
            if (!rows || !rows.length) {
                tbody.innerHTML = `<tr><td colspan="8" class="small">(no results)</td></tr>`;
            } else {
                tbody.innerHTML = rows.map(r => {
                    const rowDomain = r.domain || (resp && resp.domain) || dom || '';
                    const modeLabel = r.mode || '';
                    const cacheFlag = r.from_cache ? '<span class="hist-flag">Cache</span>' : '';
                    const timeoutUsed = Number.isFinite(Number(r.timeout_used)) ? `${r.timeout_used} ms` : (r.timeout_used ? r.timeout_used : '');
                    const retriesVal = r.retries != null ? r.retries : '';
                    const startedAtMs = normaliseTimestamp(r.started_at);
                    const finishedAtMs = normaliseTimestamp(r.finished_at);
                    let durationValue = (r.duration_ms == null ? null : Number(r.duration_ms));
                    if (!Number.isFinite(durationValue) || durationValue < 0) {
                        durationValue = null;
                    }
                    let derivedDuration = null;
                    if (startedAtMs !== null && finishedAtMs !== null && finishedAtMs >= startedAtMs) {
                        derivedDuration = finishedAtMs - startedAtMs;
                    }
                    if ((durationValue === null || durationValue === 0) && derivedDuration !== null) {
                        durationValue = derivedDuration;
                    }
                    const durationLabel = durationValue !== null ? `<span title="${Math.round(durationValue)} ms">${fmtDuration(durationValue)}</span>` : '';
                    const payloadLabel = r.payload_bytes != null ? `<span title="${r.payload_bytes} bytes">${fmtBytes(r.payload_bytes)}</span>` : '';
                    const durationDisplay = durationLabel || '<span class="ts-cell-muted">-</span>';
                    return `<tr>
            <td class="mono">${escapeHtml(rowDomain)}</td>
            <td><span class="hist-mode">${escapeHtml(modeLabel)}${cacheFlag}</span></td>
            <td>${fmtTime(r.started_at)}</td>
            <td>${fmtTime(r.finished_at)}</td>
            <td>${durationDisplay}</td>
            <td>${payloadLabel}</td>
            <td>${retriesVal}</td>
            <td>${timeoutUsed}</td>
          </tr>`;
                }).join('');
            }

            // update paging UI
            const totalPages = Math.max(1, Math.ceil((totalRows || 0) / pageSize));
            pageInfo.textContent = `Page ${totalRows ? currentPage : 0}/${totalPages}`;
            btnPrev.disabled = currentPage <= 1;
            btnFirst.disabled = currentPage <= 1;
            btnNext.disabled = currentPage >= totalPages;
            btnLast.disabled = currentPage >= totalPages;
            pagingBar.style.display = (totalRows > pageSize) ? 'flex' : 'none';

            // update summary and range
            const start = totalRows ? ((currentPage - 1) * pageSize + 1) : 0;
            const end = totalRows ? Math.min(currentPage * pageSize, totalRows) : 0;
            summary.textContent = `Total ${totalRows || 0} | Range: ${start}-${end}`;
        } catch (e) {
            console.error('loadHistory failed', e);
            tbody.innerHTML = `<tr><td colspan="8" class="small">Error: ${e && e.message ? escapeHtml(e.message) : String(e)}</td></tr>`;
        } finally {
            loading.style.display = 'none';
        }
    }

    // Paging button event listeners
    btnLast.addEventListener('click', () => {
        const tp = Math.max(1, Math.ceil(totalRows / pageSize));
        if (currentPage !== tp) {
            currentPage = tp;
            loadHistory();
        }
    });

    // other paging controls
    btnPrev && btnPrev.addEventListener('click', () => { if (currentPage > 1) { currentPage--; loadHistory(); } });
    btnNext && btnNext.addEventListener('click', () => { const tp = Math.max(1, Math.ceil(totalRows / pageSize)); if (currentPage < tp) { currentPage++; loadHistory(); } });
    btnFirst && btnFirst.addEventListener('click', () => { if (currentPage !== 1) { currentPage = 1; loadHistory(); } });

    // page size change
    pageSizeSel && pageSizeSel.addEventListener('change', () => { pageSize = parseInt(pageSizeSel.value, 10) || 20; currentPage = 1; loadHistory(); });

    // form submit -> run search
    form && form.addEventListener('submit', (e) => { e.preventDefault(); currentPage = 1; loadHistory(); });

    // Clickable header sorting (overrides dropdown values)
    document.querySelectorAll('#hist-table thead th.sortable').forEach(th => {
        th.style.cursor = 'pointer';
        th.addEventListener('click', () => {
            const k = th.dataset.sort;
            if (sortKey === k) { sortDir = (sortDir === 'asc' ? 'desc' : 'asc'); }
            else { sortKey = k; sortDir = 'asc'; }
            currentPage = 1;
            loadHistory();
        });
    });

    function updateHeaderIndicators() {
        document.querySelectorAll('#hist-table thead th.sortable').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
        const active = document.querySelector(`#hist-table thead th.sortable[data-sort='${sortKey}']`);
        if (active) { active.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc'); }
    }

    // Wrap loadHistory to update indicators after data load
    const _origLoadHistory = loadHistory;
    loadHistory = async function () {
        await _origLoadHistory();
        updateHeaderIndicators();
    }

    // Initial load (global recent history)
    loadHistory();
});
