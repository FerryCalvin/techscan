/* Extracted from websites.html */

let allDomains = []; // {domain, last_scan_ts, last_mode, tech_count, diff_added, diff_removed, diff_changed, groups:Set}
let groupsMeta = {}; // group -> [domains]
const inflightScans = new Map(); // domain -> {ctrl, started_at}
const tbody = document.querySelector('#domains-table tbody');
const filterInput = document.getElementById('filter');
const summaryEl = document.getElementById('summary');
const onlyUngroupedChk = null; // removed checkbox
let groupFilterSel = document.getElementById('group-filter');
const manageGroupsBtn = document.getElementById('manage-groups-open');
const groupsPopover = document.getElementById('group-popover');
const selectAllChk = document.getElementById('select-all');
const multiToolbar = document.getElementById('multi-toolbar');
const selCountEl = document.getElementById('sel-count');
const multiGroupSelect = document.getElementById('multi-group-select');
const multiAssignBtn = document.getElementById('multi-assign');
const multiRescanBtn = document.getElementById('multi-rescan');
const multiDeleteBtn = document.getElementById('multi-delete');
const multiClearBtn = document.getElementById('multi-clear');
const multiStatus = document.getElementById('multi-status');
let selectedDomains = new Set();
// Pagination state
let pageSize = 20;
let currentPage = 1;
const groupListDiv = document.getElementById('group-list');
const assignDlg = document.getElementById('assign-dialog');
const assignDomainEl = document.getElementById('assign-domain');
const assignSelect = document.getElementById('assign-select');
let assignTarget = null;
let sortState = { key: null, dir: 1 }; // dir: 1 asc, -1 desc
let groupSearchTerm = '';
const groupSearchInput = document.getElementById('group-search');
const groupSearchClear = document.getElementById('group-search-clear');
const toastStack = document.getElementById('toast-stack');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"]|'/g, function (ch) {
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

function formatBytes(value) {
  if (value === null || value === undefined) {
    return '-';
  }
  let bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) {
    return '-';
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

// If the `group-filter` control is missing (template markup changed), create a hidden fallback
if (!groupFilterSel) {
  try {
    const fallback = document.createElement('select');
    fallback.id = 'group-filter';
    fallback.style.display = 'none';
    fallback.innerHTML = "<option value='all'>Semua</option><option value='ungrouped'>Tanpa Grup</option>";
    // Try to append to the right-col if present, otherwise to controls-row, otherwise to body
    const rightCol = document.querySelector('.controls-row .right-col');
    const controlsRow = document.querySelector('.controls-row');
    if (rightCol) rightCol.appendChild(fallback);
    else if (controlsRow) controlsRow.appendChild(fallback);
    else document.body.appendChild(fallback);
    groupFilterSel = fallback;
  } catch (_) { /** ignore fallback failures */ }
}

function toast(msg, type = 'ok', ttl = 3500) {
  if (!toastStack) return;
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = `<span style="flex:1 1 auto;">${msg}</span><button class='close' aria-label='close'>&times;</button>`;
  toastStack.appendChild(el);
  const remove = () => { if (!el.isConnected) return; el.style.transition = 'opacity .18s ease, transform .18s ease'; el.style.opacity = '0'; el.style.transform = 'translateY(6px)'; setTimeout(() => el.remove(), 190); };
  el.querySelector('.close').addEventListener('click', remove);
  setTimeout(remove, ttl);
}

function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : 'never'; }

async function loadAll() {
  tbody.innerHTML = '<tr><td colspan="10" class="small">Loading...</td></tr>';
  try {
    const data = await apiFetch('/api/domains');
    buildFlat(data);
    summaryEl.textContent = `Total ${data.summary.total_domains} | Scanned ${data.summary.scanned} | Unscanned ${data.summary.unscanned}`;
    renderTable();
    loadGroupsMeta();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan='10' class='small'>Error ${e.message}</td></tr>`;
  }
}

function buildFlat(payload) {
  const domainMap = new Map();
  // groups
  (payload.groups || []).forEach(g => {
    g.domains.forEach(d => {
      let rec = domainMap.get(d.domain);
      if (!rec) {
        rec = { ...d, groups: new Set() };
        domainMap.set(d.domain, rec);
      }
      rec.groups.add(g.key);
    });
  });
  // ungrouped
  (payload.ungrouped || []).forEach(d => {
    if (!domainMap.has(d.domain)) domainMap.set(d.domain, { ...d, groups: new Set() });
  });
  allDomains = Array.from(domainMap.values()).sort((a, b) => (a.domain < b.domain ? -1 : 1));
}

async function loadGroupsMeta() {
  try { const meta = await apiFetch('/api/domain_groups'); groupsMeta = meta.groups || {}; renderGroupList(); }
  catch (e) { groupListDiv.textContent = 'Failed to load groups: ' + e.message; }
  refreshMultiGroupOptions();
}

function renderGroupList() {
  const entries = Object.entries(groupsMeta).sort((a, b) => a[0].localeCompare(b[0]));
  const filtered = groupSearchTerm ? entries.filter(([g]) => g.toLowerCase().includes(groupSearchTerm)) : entries;
  if (!filtered.length) { groupListDiv.innerHTML = '<em class="small empty" >(tidak ada grup)</em>'; return; }
  groupListDiv.innerHTML = filtered.map(([g, arr]) => {
    const count = arr.length;
    return `<div class='grp-row' style='display:flex; align-items:center; gap:.35rem; margin-bottom:.3rem;'>
      <span class='grp-name' data-group='${g}' style='flex:1 1 auto; word-break:break-all; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:.35rem;'>
        <span style='flex:1 1 auto;'>${g}</span>
        <span class='badge grp-count-badge'>${count}</span>
      </span>
      <button class='secondary outline export' data-group='${g}' title='Export CSV' style='font-size:.5rem;padding:2px 5px;'>↧</button>
      <button class='secondary outline x-del' data-group='${g}' title='Hapus'>×</button>
    </div>`;
  }).join('');
  groupListDiv.querySelectorAll('.x-del').forEach(btn => btn.addEventListener('click', () => deleteGroup(btn.dataset.group)));
  groupListDiv.querySelectorAll('.export').forEach(btn => btn.addEventListener('click', () => exportGroupCSV(btn.dataset.group)));
  groupListDiv.querySelectorAll('.grp-name').forEach(span => span.addEventListener('dblclick', () => startRename(span.dataset.group, span)));
}

function renderTable() {
  const term = (filterInput?.value || '').toLowerCase();
  const onlyUng = false; // replaced by groupFilterSel option 'ungrouped'
  const gf = (groupFilterSel?.value) ? groupFilterSel.value : 'all';
  let rows = allDomains.filter(d => {
    if (term && !d.domain.toLowerCase().includes(term)) return false;
    if (gf === 'ungrouped' && d.groups && d.groups.size) return false;
    if (gf !== 'all' && gf !== 'ungrouped') {
      // show only domains that have this group
      if (!d.groups || !d.groups.has(gf)) return false;
    }
    return true;
  });
  // sort
  if (sortState.key) {
    const k = sortState.key;
    const dir = sortState.dir;
    rows.sort((a, b) => {
      if (k === 'domain') return a.domain.localeCompare(b.domain) * dir;
      if (k === 'tech') return ((a.tech_count || 0) - (b.tech_count || 0)) * dir;
      if (k === 'last_scan') return ((a.last_scan_ts || 0) - (b.last_scan_ts || 0)) * dir;
      if (k === 'payload') return ((a.payload_bytes || 0) - (b.payload_bytes || 0)) * dir;
      return 0;
    });
  }
  const total = rows.length;
  if (!total) {
    tbody.innerHTML = '<tr><td colspan="10" class="small">(no results)</td></tr>';
    updatePaging(total);
    return;
  }
  // Adjust currentPage if overflow
  const totalPages = Math.ceil(total / pageSize) || 1;
  if (currentPage > totalPages) currentPage = 1;
  const start = (currentPage - 1) * pageSize;
  const slice = rows.slice(start, start + pageSize);
  tbody.innerHTML = slice.map((r, i) => rowHTML(r, start + i)).join('');
  // Set header checkbox state for current page
  if (selectAllChk) {
    const allSelected = slice.every(d => selectedDomains.has(d.domain));
    selectAllChk.checked = allSelected && slice.length > 0;
  }
  updatePaging(total);
  tbody.querySelectorAll('tr.row-detail').forEach(tr => {
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('.grp-badge')) return;
      if (ev.target.closest('.actions')) return;
      if (ev.target.closest('input.row-select')) return;
      showDetail(tr.dataset.domain);
    });
    const addBtn = tr.querySelector('.assign-btn');
    addBtn && addBtn.addEventListener('click', (e) => { e.stopPropagation(); openAssign(tr.dataset.domain); });
    tr.querySelectorAll('.grp-badge .rm').forEach(b => b.addEventListener('click', (e) => { e.stopPropagation(); removeFromGroup(tr.dataset.domain, b.dataset.group); }));
    const delBtn = tr.querySelector('.del-btn');
    delBtn && delBtn.addEventListener('click', (e) => { e.stopPropagation(); deleteDomain(tr.dataset.domain, delBtn); });
  });
  tbody.querySelectorAll('input.row-select').forEach(cb => {
    cb.addEventListener('change', () => {
      const domain = cb.dataset.domain;
      if (cb.checked) selectedDomains.add(domain); else selectedDomains.delete(domain);
      updateMultiToolbar();
    });
  });
  updateMultiToolbar();
}

function rowHTML(r, idx) {
  const groups = Array.from(r.groups || []).sort();
  const groupBadges = groups.map(g => {
    const safe = escapeHtml(g);
    return `<span class='grp-badge' title='${safe}'>${safe}<button class='rm' data-group='${escapeHtml(g)}' title='Hapus dari grup'>&times;</button></span>`;
  }).join(' ');
  const last = fmtTime(r.last_scan_ts);
  const payload = formatBytes(r.payload_bytes);
  const diff = (r.diff_added || 0) || (r.diff_removed || 0) || (r.diff_changed || 0) ? `<span class='badge diff-added'>+${r.diff_added || 0}</span><span class='badge diff-removed'>-${r.diff_removed || 0}</span><span class='badge diff-changed'>±${r.diff_changed || 0}</span>` : '';
  const checked = selectedDomains.has(r.domain) ? 'checked' : '';
  // highlight search term
  const domainRaw = r.domain || '';
  const term = (filterInput?.value || '').trim().toLowerCase();
  let domainLabel;
  if (term) {
    const lower = domainRaw.toLowerCase();
    const hit = lower.indexOf(term);
    if (hit !== -1) {
      const pre = escapeHtml(domainRaw.slice(0, hit));
      const match = escapeHtml(domainRaw.slice(hit, hit + term.length));
      const post = escapeHtml(domainRaw.slice(hit + term.length));
      domainLabel = pre + '<mark class="hl">' + match + '</mark>' + post;
    } else {
      domainLabel = escapeHtml(domainRaw);
    }
  } else {
    domainLabel = escapeHtml(domainRaw);
  }
  return `<tr class='row-detail' data-domain='${escapeHtml(domainRaw)}' style='cursor:pointer;'>
    <td class='mono' style='text-align:right;opacity:.7;'>${idx + 1}</td>
    <td><input type='checkbox' class='row-select' data-domain='${escapeHtml(domainRaw)}' ${checked} /></td>
    <td class='mono' style='word-break:break-all;'>${domainLabel}</td>
    <td>${groupBadges || '<span class="small" style="opacity:.5">(none)</span>'}</td>
    <td>${r.tech_count || 0}</td>
    <td>${last}</td>
  <td>${payload}</td>
    <td>${r.last_mode || ''}</td>
    <td>${diff}</td>
  <td class='actions'><button class='secondary outline assign-btn' style='font-size:.55rem;padding:4px 12px;gap:2px;'>Assign</button> <button class='secondary outline del-btn' data-domain='${r.domain}' style='font-size:.55rem;padding:4px 12px;margin-left:4px;gap:2px;' title='Hapus domain'>
      <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
    </button></td>
  </tr>`;
}

filterInput && filterInput.addEventListener('input', () => renderTable());
groupFilterSel && groupFilterSel.addEventListener('change', () => renderTable());
selectAllChk && selectAllChk.addEventListener('change', () => {
  if (selectAllChk.checked) {
    tbody.querySelectorAll('tr.row-detail').forEach(tr => selectedDomains.add(tr.dataset.domain)); // only current page
  } else {
    tbody.querySelectorAll('tr.row-detail').forEach(tr => selectedDomains.delete(tr.dataset.domain));
  }
  renderTable();
});
multiClearBtn && multiClearBtn.addEventListener('click', () => { selectedDomains.clear(); if (selectAllChk) selectAllChk.checked = false; renderTable(); });
multiAssignBtn && multiAssignBtn.addEventListener('click', batchAssignSelected);
multiRescanBtn && multiRescanBtn.addEventListener('click', batchRescanSelected);
multiDeleteBtn && multiDeleteBtn.addEventListener('click', batchDeleteSelected);
// Pagination controls
const pageSizeSel = document.getElementById('page-size');
const pagePrevBtn = document.getElementById('page-prev');
const pageNextBtn = document.getElementById('page-next');
const pageFirstBtn = document.getElementById('page-first');
const pageLastBtn = document.getElementById('page-last');
const pageInfoSpan = document.getElementById('page-info');

// Load persisted page size
try {
  const storedSz = localStorage.getItem('ts_page_size');
  if (storedSz && pageSizeSel && [...pageSizeSel.options].some(o => o.value === storedSz)) {
    pageSizeSel.value = storedSz;
    pageSize = parseInt(storedSz, 10) || pageSize;
  }
} catch (_) {/* ignore */ }

pageSizeSel && pageSizeSel.addEventListener('change', () => {
  pageSize = parseInt(pageSizeSel.value, 10) || 20;
  try { localStorage.setItem('ts_page_size', String(pageSize)); } catch (_) { }
  currentPage = 1;
  renderTable();
});
pagePrevBtn && pagePrevBtn.addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderTable(); } });
pageNextBtn && pageNextBtn.addEventListener('click', () => { currentPage++; renderTable(); });
pageFirstBtn && pageFirstBtn.addEventListener('click', () => { if (currentPage !== 1) { currentPage = 1; renderTable(); } });
pageLastBtn && pageLastBtn.addEventListener('click', () => { const totalRows = getCurrentFilteredCount(); const tp = Math.max(1, Math.ceil(totalRows / pageSize)); if (currentPage !== tp) { currentPage = tp; renderTable(); } });

function getCurrentFilteredCount() {
  const term = (filterInput?.value || '').toLowerCase();
  const gf = (groupFilterSel?.value) ? groupFilterSel.value : 'all';
  return allDomains.filter(d => {
    if (term && !d.domain.toLowerCase().includes(term)) return false;
    if (gf === 'ungrouped' && d.groups && d.groups.size) return false;
    if (gf !== 'all' && gf !== 'ungrouped' && (!d.groups || !d.groups.has(gf))) return false;
    return true;
  }).length;
}

function updatePaging(total) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (currentPage > totalPages) currentPage = totalPages;
  if (pageInfoSpan) pageInfoSpan.textContent = `Page ${total ? currentPage : 0}/${totalPages}`;
  if (pagePrevBtn) pagePrevBtn.disabled = currentPage <= 1;
  if (pageNextBtn) pageNextBtn.disabled = currentPage >= totalPages;
  if (pageFirstBtn) pageFirstBtn.disabled = currentPage <= 1;
  if (pageLastBtn) pageLastBtn.disabled = currentPage >= totalPages;
  // Update summary with range
  if (summaryEl) {
    const start = total ? ((currentPage - 1) * pageSize + 1) : 0;
    const end = total ? Math.min(currentPage * pageSize, total) : 0;
    // Keep existing summary prefix (already set in loadAll) then append range
    const base = summaryEl.textContent.split(' | Range: ')[0];
    summaryEl.textContent = base + ` | Range: ${start}-${end} dari ${total}`;
  }
  // trigger fade animation
  if (tbody) {
    tbody.classList.remove('page-fade');
    void tbody.offsetWidth; // reflow
    tbody.classList.add('page-fade');
  }
}

async function deleteDomain(domain, btn) {
  if (!confirm('Hapus domain ' + domain + '?')) return;
  const original = btn ? btn.textContent : '';
  if (btn) { btn.textContent = '...'; btn.disabled = true; }
  try {
    await jsonReq(`/api/domain/${encodeURIComponent(domain)}`, { method: 'DELETE' });
    selectedDomains.delete(domain);
    await loadAll();
    toast('Domain deleted', 'ok');
  } catch (e) {
    console.error('delete_domain_failed', domain, e);
    alert('Failed to delete domain: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = original || 'Hapus'; }
  }
}

// Sorting event
document.querySelectorAll('#domains-table thead th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortState.key === key) { sortState.dir = -sortState.dir; }
    else { sortState.key = key; sortState.dir = 1; }
    document.querySelectorAll('#domains-table thead th.sortable').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
    th.classList.add(sortState.dir === 1 ? 'sorted-asc' : 'sorted-desc');
    renderTable();
  });
});

// Sticky header shadow
const tableEl = document.getElementById('domains-table');
tableEl && tableEl.parentElement.addEventListener('scroll', () => {
  const sc = tableEl.parentElement.scrollTop;
  tableEl.classList.toggle('table-shadow', sc > 4);
});

// Group search handlers
if (groupSearchInput) {
  groupSearchInput.addEventListener('input', () => { groupSearchTerm = (groupSearchInput.value || '').trim().toLowerCase(); renderGroupList(); });
}
if (groupSearchClear) {
  groupSearchClear.addEventListener('click', () => { groupSearchTerm = ''; if (groupSearchInput) groupSearchInput.value = ''; renderGroupList(); });
}

// Inline rename
function startRename(oldName, spanEl) {
  if (!spanEl) return; // guard
  const pure = oldName;
  const input = document.createElement('input');
  input.type = 'text';
  input.value = pure;
  input.style.width = '100%';
  input.style.fontSize = '0.65rem';
  spanEl.replaceWith(input);
  input.focus();
  input.select();
  let done = false;
  const finish = async (commit) => {
    if (done) return; done = true;
    const val = (input.value || '').trim();
    if (!commit || !val || val === pure) { renderGroupList(); return; }
    try {
      await jsonReq(`/api/domain_groups/${encodeURIComponent(pure)}/rename`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ new: val }) });
      toast('Rename: ' + pure + ' -> ' + val, 'ok');
      await loadGroupsMeta();
      await loadAll();
    } catch (e) { toast('Rename failed: ' + e.message, 'err'); }
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); finish(false); }
    else if (e.key === 'Enter') { e.preventDefault(); finish(true); }
  });
  input.addEventListener('blur', () => finish(true));
}

// Export group domains to CSV
function exportGroupCSV(group) {
  const list = groupsMeta[group] || [];
  if (!list.length) { toast('Group is empty', 'err'); return; }
  const map = new Map(allDomains.map(d => [d.domain, d]));
  const header = 'domain,tech_count,last_scan_ts,last_scan_iso\n';
  const rows = list.map(d => {
    const rec = map.get(d) || {};
    const ts = rec.last_scan_ts || '';
    const iso = ts ? new Date(ts * 1000).toISOString() : '';
    return `${d},${rec.tech_count || 0},${ts},${iso}`;
  });
  const blob = new Blob([header + rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'group_' + group + '.csv'; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
  toast('Export ' + group, 'ok');
}

function exportAllGroups() {
  const keys = Object.keys(groupsMeta || {}).sort();
  if (!keys.length) { toast('No groups available', 'err'); return; }
  let exported = 0; keys.forEach((g, i) => setTimeout(() => { try { exportGroupCSV(g); exported++; if (exported === keys.length) toast('All exports completed', 'ok'); } catch (e) { } }, i * 160));
}
document.getElementById('export-all-groups')?.addEventListener('click', exportAllGroups);

function updateMultiToolbar() {
  const count = selectedDomains.size;
  selCountEl.textContent = count + ' selected';
  multiToolbar.style.display = count ? 'flex' : 'none';
  multiAssignBtn.disabled = !count || !multiGroupSelect.value;
  if (multiRescanBtn) multiRescanBtn.disabled = !count;
  if (multiDeleteBtn) multiDeleteBtn.disabled = !count;
}

function refreshMultiGroupOptions() {
  const opts = Object.keys(groupsMeta || {}).sort();
  multiGroupSelect.innerHTML = '<option value="">-- select group --</option>' + opts.map(o => {
    const c = (groupsMeta[o] || []).length; return `<option value='${o}'>${o} (${c})</option>`;
  }).join('');
  // group filter options
  if (groupFilterSel) {
    const cur = groupFilterSel.value;
    groupFilterSel.innerHTML = `<option value='all'>All</option><option value='ungrouped'>Ungrouped</option>` + opts.map(o => {
      const c = (groupsMeta[o] || []).length; return `<option value='${o}'>${o} (${c})</option>`;
    }).join('');
    if (cur && [...groupFilterSel.options].some(o => o.value === cur)) groupFilterSel.value = cur; else groupFilterSel.value = 'all';
  }
  if (!multiGroupSelect.onchange) multiGroupSelect.addEventListener('change', updateMultiToolbar);
  updateMultiToolbar();
}

// Generic helper for JSON fetch with detailed error surfacing
async function jsonReq(url, opts = {}) {
  const timeoutMs = opts.timeoutMs || 8000;
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), timeoutMs);
  const resp = await fetch(url, { ...opts, signal: ctrl.signal });
  clearTimeout(to);
  let bodyText = '';
  try { bodyText = await resp.text(); } catch (_) { bodyText = ''; }
  let parsed = null;
  try { parsed = bodyText ? JSON.parse(bodyText) : null; } catch (_) { /* ignore */ }
  if (!resp.ok) {
    const msg = (parsed && (parsed.error || parsed.detail)) || resp.status + ':' + resp.statusText;
    console.error('Request failed', { url, status: resp.status, body: bodyText });
    throw new Error(msg);
  }
  return parsed;
}

// Group CRUD
const addGroupBtn = document.getElementById('add-group');
addGroupBtn && addGroupBtn.addEventListener('click', async () => {
  const ng = document.getElementById('new-group');
  const name = ng ? ng.value.trim() : '';
  if (!name) { alert('Nama grup kosong'); return; }
  addGroupBtn.disabled = true; const prevTxt = addGroupBtn.textContent; addGroupBtn.textContent = '...';
  try {
    const resp = await jsonReq('/api/domain_groups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ group: name }) });
    console.log('ADD_GROUP_OK', resp);
    if (ng) ng.value = '';
    await loadGroupsMeta();
    // refresh domain memberships completely
    await loadAll();
    toast('Group added', 'ok');
  } catch (e) {
    console.error('ADD_GROUP_FAIL', e);
    toast('Failed to add group: ' + e.message, 'err');
  } finally { addGroupBtn.disabled = false; addGroupBtn.textContent = prevTxt || 'Tambah'; }
});

async function deleteGroup(g) {
  if (!confirm('Hapus grup ' + g + '?')) return;
  const btn = [...groupListDiv.querySelectorAll('.x-del')].find(b => b.dataset.group === g);
  if (btn) { btn.disabled = true; const old = btn.textContent; btn.textContent = '...'; btn.dataset._old = old; }
  try {
    const resp = await jsonReq('/api/domain_groups/' + encodeURIComponent(g), { method: 'DELETE' });
    console.log('DEL_GROUP_OK', g, resp);
    await loadGroupsMeta();
    // full reload to stay consistent
    await loadAll();
    toast('Group deleted', 'ok');
  } catch (e) { alert('Failed to delete: ' + e.message); }
  finally { if (btn) { btn.disabled = false; btn.textContent = btn.dataset._old || 'Hapus'; delete btn.dataset._old; } }
}

function openAssign(domain) {
  assignTarget = domain;
  assignDomainEl.textContent = domain;
  // options groups not already present
  const domainRec = allDomains.find(d => d.domain === domain);
  const present = domainRec ? domainRec.groups : new Set();
  const options = Object.keys(groupsMeta).filter(g => !present.has(g)).sort();
  assignSelect.innerHTML = options.map(o => `<option value='${o}'>${o}</option>`).join('');
  if (!options.length) { assignSelect.innerHTML = '<option value="" disabled>(tidak ada grup tersedia)</option>'; }
  assignDlg.showModal();
}

const assignCancelBtn = document.getElementById('assign-cancel');
assignCancelBtn && assignCancelBtn.addEventListener('click', () => assignDlg.close());
const assignSaveBtn = document.getElementById('assign-save');
assignSaveBtn && assignSaveBtn.addEventListener('click', async () => {
  const g = assignSelect.value; if (!g) { assignDlg.close(); return; }
  assignSaveBtn.disabled = true; const oldTxt = assignSaveBtn.textContent; assignSaveBtn.textContent = '...';
  try {
    await jsonReq(`/api/domain_groups/${encodeURIComponent(g)}/assign`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: assignTarget }) });
    assignDlg.close();
    await loadGroupsMeta();
    await loadAll();
    toast('Assigned to ' + g, 'ok');
  } catch (e) { alert('Failed to assign: ' + e.message); }
  finally { assignSaveBtn.disabled = false; assignSaveBtn.textContent = oldTxt || 'Simpan'; }
});

async function removeFromGroup(domain, g) {
  const rowBtn = tbody.querySelector(`tr[data-domain='${domain}'] .grp-badge button.rm[data-group='${g}']`);
  if (rowBtn) { rowBtn.disabled = true; const old = rowBtn.textContent; rowBtn.textContent = '.'; rowBtn.dataset._old = old; }
  try {
    const resp = await jsonReq(`/api/domain_groups/${encodeURIComponent(g)}/remove`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) });
    console.log('REMOVE_FROM_GROUP_OK', { domain, g, resp });
    await loadGroupsMeta();
    await loadAll();
    toast('Removed from ' + g, 'ok');
  } catch (e) { alert('Failed to remove from group: ' + e.message); }
  finally { if (rowBtn) { rowBtn.disabled = false; rowBtn.textContent = rowBtn.dataset._old || '×'; delete rowBtn.dataset._old; } }
}

async function batchAssignSelected() {
  const group = multiGroupSelect.value;
  if (!group) { alert('Pilih grup terlebih dahulu'); return; }
  if (!selectedDomains.size) { return; }
  multiAssignBtn.disabled = true; multiStatus.textContent = 'Assign...';
  let ok = 0, fail = 0;
  for (const d of Array.from(selectedDomains)) {
    try {
      const resp = await jsonReq(`/api/domain_groups/${encodeURIComponent(group)}/assign`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: d }) });
      console.log('BATCH_ASSIGN_OK', d, resp);
      ok++;
    } catch (e) { fail++; console.error('assign_failed', d, e); }
  }
  multiStatus.textContent = `Done: ${ok} ok, ${fail} failed`;
  await loadGroupsMeta();
  await loadAll();
  selectedDomains.clear();
  if (selectAllChk) selectAllChk.checked = false;
  renderTable();
  setTimeout(() => { multiStatus.textContent = ''; updateMultiToolbar(); }, 4000);
  if (ok) toast(`${ok} domain -> ${group}`, 'ok');
  if (fail) toast(`${fail} failed to assign`, 'err');
}

async function batchRescanSelected() {
  if (!selectedDomains.size) { return; }
  if (multiRescanBtn) multiRescanBtn.disabled = true;
  multiStatus.textContent = 'Rescan...';
  let ok = 0, fail = 0; let i = 0; const total = selectedDomains.size;
  for (const d of Array.from(selectedDomains)) {
    i++;
    multiStatus.textContent = `Scanning ${i}/${total}...`;
    try {
      await fetch('/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: d, fast_full: 1 }) });
      ok++;
    } catch (e) { fail++; console.error('rescan_failed', d, e); }
  }
  multiStatus.textContent = `Rescan done: ${ok} ok, ${fail} failed`;
  // keep selection so user can maybe assign after scan; do not clear
  setTimeout(async () => { await loadAll(); renderTable(); }, 1000);
  setTimeout(() => { multiStatus.textContent = ''; updateMultiToolbar(); }, 6000);
  if (ok) toast(`${ok} domain di-rescan`, 'ok');
  if (fail) toast(`${fail} failed to rescan`, 'err');
}

async function batchDeleteSelected() {
  if (!selectedDomains.size) return;
  if (!confirm('Hapus ' + selectedDomains.size + ' domain terpilih?')) return;
  const domains = Array.from(selectedDomains);
  if (multiDeleteBtn) multiDeleteBtn.disabled = true;
  multiStatus.textContent = 'Delete...';
  let ok = 0, fail = 0;
  for (const d of domains) {
    try {
      await jsonReq(`/api/domain/${encodeURIComponent(d)}`, { method: 'DELETE' });
      selectedDomains.delete(d);
      ok++;
    } catch (e) {
      fail++;
      console.error('batch_delete_failed', d, e);
    }
  }
  await loadAll();
  multiStatus.textContent = `Delete done: ${ok} ok, ${fail} failed`;
  if (multiDeleteBtn) multiDeleteBtn.disabled = false;
  setTimeout(() => { multiStatus.textContent = ''; updateMultiToolbar(); }, 4000);
  toast(`${ok} domains deleted`, 'ok');
  if (fail) toast(`${fail} failed to delete`, 'err');
}

// Detail dialog logic (reused from previous version)
const dlg = document.getElementById('detail-dialog');
const detailTitle = document.getElementById('detail-title');
const detailSubtitle = document.getElementById('detail-subtitle');
const detailLastScan = document.getElementById('detail-last-scan');
const detailPrevScan = document.getElementById('detail-prev-scan');
const detailModeLabel = document.getElementById('detail-mode');
const detailTechCountLabel = document.getElementById('detail-tech-count');
const detailPayloadLabel = document.getElementById('detail-payload');
const detailStatusLabel = document.getElementById('detail-status');
const detailTechSummary = document.getElementById('detail-tech-summary');
const techTbody = document.querySelector('#detail-tech-table tbody');
const diffAdded = document.getElementById('diff-added');
const diffRemoved = document.getElementById('diff-removed');
const diffChanged = document.getElementById('diff-changed');
const openDomainBtn = document.getElementById('open-domain-btn');
const viewArchivedBtn = document.getElementById('view-archived');

openDomainBtn && openDomainBtn.addEventListener('click', () => {
  const domain = openDomainBtn.dataset.domain;
  if (!domain) return;
  const url = /^https?:\/\//i.test(domain) ? domain : `https://${domain}`;
  window.open(url, '_blank');
});

async function showDetail(domain) {
  detailTitle.textContent = domain;
  detailSubtitle.innerHTML = '';
  detailLastScan.textContent = 'Loading...';
  detailPrevScan.textContent = '';
  detailModeLabel.textContent = '-';
  detailTechCountLabel.textContent = '-';
  detailPayloadLabel.textContent = '-';
  detailStatusLabel.textContent = '';
  detailTechSummary.textContent = '';
  useBestSnapshot = false;
  if (viewArchivedBtn) {
    viewArchivedBtn.textContent = 'Load Best';
  }
  if (openDomainBtn) { openDomainBtn.dataset.domain = domain; }
  techTbody.innerHTML = '<tr><td colspan="4" class="small">Loading...</td></tr>';
  diffAdded.innerHTML = diffRemoved.innerHTML = diffChanged.innerHTML = '';
  dlg.showModal();
  const loader = document.getElementById('detail-loader');
  loader.style.display = 'flex';
  try {
    // Load persisted detail and render (re-usable renderer below)
    const data = await apiFetch(`/api/domain/${domain}/detail`);
    renderDetailData(domain, data);
  } catch (e) {
    techTbody.innerHTML = `<tr><td colspan='4' class='small'>Error ${e.message}</td></tr>`;
  } finally { loader.style.display = 'none'; }
}

// Tech Icon Helper
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
  return `<div class='tech-logo' style='display:inline-block;width:20px;height:20px;vertical-align:middle;margin-right:8px;'><img src='${localPath}' alt='${name}' title='${title}' style='width:100%;height:100%;object-fit:contain;' onerror="this.onerror=null;this.parentElement.innerHTML='<div class=\\'tech-icon\\' style=\\'background:'+iconColorFor(this.parentElement.title)+'\\' title=\\''+this.parentElement.title+'\\'>'+this.parentElement.title.charAt(0).toUpperCase()+'</div>'"/></div>`;
}

function iconColorFor(name) {
  if (!name) return '#ccc';
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
  return '#' + '00000'.substring(0, 6 - c.length) + c;
}

function renderDetailData(domain, data) {
  // Prefer selected_scan metadata when provided by the detail API
  const snapshot = data.selected_scan || data.latest || data;
  const snapshotTag = (data.selected_snapshot || 'latest').toLowerCase();
  useBestSnapshot = snapshotTag === 'best';
  if (viewArchivedBtn) {
    viewArchivedBtn.textContent = useBestSnapshot ? 'Load Latest' : 'Load Best';
  }

  const historyUrl = `/history?domain=${encodeURIComponent(domain)}`;
  const historyLink = `<a href='${historyUrl}' target='_blank' rel='noopener'>Open history</a>`;
  const compareSnapshot = data.compare_snapshot || data.previous || null;
  const latestSummary = data.latest || null;
  const finishedAt = snapshot && (snapshot.finished_at || snapshot.timestamp);
  detailLastScan.textContent = finishedAt ? new Date(finishedAt * 1000).toLocaleString() : '-';

  if (useBestSnapshot && latestSummary && snapshot && latestSummary.scan_id !== snapshot.scan_id) {
    detailPrevScan.textContent = latestSummary.finished_at
      ? 'Latest: ' + new Date(latestSummary.finished_at * 1000).toLocaleString()
      : 'Latest scan available';
  } else if (compareSnapshot && compareSnapshot.finished_at) {
    detailPrevScan.textContent = 'Prev: ' + new Date(compareSnapshot.finished_at * 1000).toLocaleString();
  } else {
    detailPrevScan.textContent = '';
  }

  const scanId = (snapshot && snapshot.scan_id) || data.scan_id || null;
  const scanLabel = useBestSnapshot ? 'Best snapshot' : 'Scan ID';
  if (scanId) {
    detailSubtitle.innerHTML = `${scanLabel} <span class="mono">${escapeHtml(String(scanId))}</span> &middot; ${historyLink}`;
  } else {
    detailSubtitle.innerHTML = historyLink;
  }

  detailModeLabel.textContent = (snapshot && snapshot.mode) ? snapshot.mode : '-';

  const payloadBytes = (snapshot && snapshot.payload_bytes !== undefined && snapshot.payload_bytes !== null)
    ? snapshot.payload_bytes
    : (data.payload_bytes ?? null);
  detailPayloadLabel.textContent = (payloadBytes !== null && payloadBytes !== undefined)
    ? formatBytes(payloadBytes)
    : '-';

  const techs = data.technologies || (snapshot && snapshot.technologies) || [];
  detailTechCountLabel.textContent = `${techs.length} technologies`;
  if (data.status === 'in-progress') {
    detailTechSummary.textContent = `Live scan in progress${data.eta_seconds ? ` - ETA ~${data.eta_seconds}s` : ''}`;
  } else if (useBestSnapshot) {
    detailTechSummary.textContent = 'Showing best historical snapshot';
  } else if (snapshot && snapshot.mode) {
    detailTechSummary.textContent = `Last mode: ${snapshot.mode}`;
  } else {
    detailTechSummary.textContent = '';
  }

  const statusBits = [];
  if (useBestSnapshot) statusBits.push('Best snapshot');
  if (data.status === 'in-progress') statusBits.push('In progress');
  if (snapshot && snapshot.mode) statusBits.push(snapshot.mode);
  if (finishedAt) statusBits.push('Completed');
  detailStatusLabel.textContent = statusBits.join(' | ');

  techTbody.innerHTML = '';
  const added = (data.diff && data.diff.added) || [];
  const changed = (data.diff && data.diff.changed) || [];
  const addedNames = new Set(added.map(x => x.name));
  const changedNames = new Set(changed.map(x => x.name));
  (techs || []).forEach(t => {
    const tr = document.createElement('tr');
    if (addedNames.has(t.name)) tr.classList.add('diff-added');
    else if (changedNames.has(t.name)) tr.classList.add('diff-changed');
    const nameTd = document.createElement('td');
    nameTd.style.display = 'flex';
    nameTd.style.alignItems = 'center';
    nameTd.style.gap = '0.5rem';

    const infoBtn = document.createElement('button');
    infoBtn.className = 'icon-btn';
    infoBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    infoBtn.title = 'View Evidence';
    infoBtn.onclick = (e) => { e.stopPropagation(); showEvidence(t); };

    // Icon wrapper
    const iconWrapper = document.createElement('span');
    iconWrapper.innerHTML = techIconHTML(t.name, t.version);

    const nameSpan = document.createElement('span');
    nameSpan.textContent = t.name;

    nameTd.appendChild(infoBtn);
    nameTd.appendChild(iconWrapper);
    nameTd.appendChild(nameSpan);
    tr.appendChild(nameTd);

    const verTd = document.createElement('td'); verTd.textContent = t.version || ''; tr.appendChild(verTd);
    const catTd = document.createElement('td'); catTd.textContent = (t.categories || []).join(', '); tr.appendChild(catTd);
    const confTd = document.createElement('td'); confTd.textContent = t.confidence || ''; tr.appendChild(confTd);

    techTbody.appendChild(tr);
  });
  if (!techTbody.children.length) { techTbody.innerHTML = '<tr><td colspan="4" class="small">(no technologies)</td></tr>'; }

  diffAdded.innerHTML = '';
  diffRemoved.innerHTML = '';
  diffChanged.innerHTML = '';
  (added || []).forEach(a => { const li = document.createElement('li'); li.className = 'diff-added'; li.textContent = a.name + (a.version ? ' ' + a.version : ''); diffAdded.appendChild(li); });
  (data.diff && data.diff.removed || []).forEach(r => { const li = document.createElement('li'); li.className = 'diff-removed'; li.textContent = r.name + (r.version ? ' ' + r.version : ''); diffRemoved.appendChild(li); });
  (changed || []).forEach(c => { const li = document.createElement('li'); li.className = 'diff-changed'; li.textContent = `${c.name}: ${c.from || '(none)'} -> ${c.to || '(none)'}`; diffChanged.appendChild(li); });
  if (!diffAdded.children.length) diffAdded.innerHTML = '<li class="small">(none)</li>';
  if (!diffRemoved.children.length) diffRemoved.innerHTML = '<li class="small">(none)</li>';
  if (!diffChanged.children.length) diffChanged.innerHTML = '<li class="small">(none)</li>';
}

let useBestSnapshot = false;
async function triggerRescan() {
  const domain = detailTitle.textContent; const btn = document.getElementById('rescan-btn');
  if (!domain) return;
  // Prevent duplicate in-flight scans
  if (inflightScans.has(domain)) {
    toast('Scan sudah berjalan untuk ' + domain, 'err');
    return;
  }
  btn.disabled = true; btn.textContent = 'Scanning...';
  // Abortable fetch with timeout
  const ctrl = new AbortController();
  const timeoutMs = 60000; // 60s
  const to = setTimeout(() => { ctrl.abort(); }, timeoutMs);
  inflightScans.set(domain, { ctrl, started_at: Date.now() });
  try {
    const resp = await fetch(`/scan?domain=${encodeURIComponent(domain)}&force=1`, { signal: ctrl.signal });
    clearTimeout(to);
    if (!resp.ok) throw new Error('scan request failed: ' + resp.status + ' ' + resp.statusText);
    const data = await resp.json();
    // Render returned live data immediately
    renderDetailData(domain, data);
    toast('Scan completed', 'ok');
  } catch (e) {
    if (e.name === 'AbortError') toast('Scan cancelled due to timeout', 'err');
    else toast('Scan failed: ' + (e.message || e), 'err');
  } finally {
    inflightScans.delete(domain);
    clearTimeout(to);
    // Small cooldown to prevent immediate spam
    setTimeout(() => { btn.disabled = false; btn.textContent = 'Re-Scan'; }, 8000);
  }
}
const rescanBtn = document.getElementById('rescan-btn');
rescanBtn && rescanBtn.addEventListener('click', triggerRescan);
const detailCloseBtn = document.getElementById('detail-close');
detailCloseBtn && detailCloseBtn.addEventListener('click', () => dlg.close());

if (viewArchivedBtn) {
  viewArchivedBtn.addEventListener('click', async () => {
    useBestSnapshot = !useBestSnapshot;
    viewArchivedBtn.textContent = useBestSnapshot ? 'Load Latest' : 'Load Best';
    try {
      const domain = detailTitle.textContent;
      if (!domain) return;
      const url = useBestSnapshot ? `/api/domain/${encodeURIComponent(domain)}/detail?snapshot=best` : `/api/domain/${encodeURIComponent(domain)}/detail`;
      const data = await apiFetch(url);
      renderDetailData(domain, data);
      toast(useBestSnapshot ? 'Loaded best snapshot' : 'Loaded latest scan', 'ok');
    } catch (e) {
      toast('Failed to load snapshot: ' + (e.message || e), 'err');
    }
  });
}

// Style group badge
const style = document.createElement('style');
style.textContent = `.grp-badge{display:inline-flex;align-items:center;gap:2px;background:var(--ts-badge-group-bg);padding:2px 4px;border-radius:4px;font-size:0.55rem;color:var(--ts-badge-group-text);} .grp-badge button.rm{background:none;border:none;color:var(--ts-danger-soft);cursor:pointer;font-size:.7rem;line-height:1;padding:0 2px;} .grp-badge button.rm:hover{color:var(--ts-danger);} tr.row-detail:hover{background:rgba(255,255,255,0.03);} #multi-toolbar{font-size:0.65rem;} #multi-toolbar select,#multi-toolbar button{font-size:0.6rem;padding:2px 6px;} .grp-count-badge{background:var(--ts-badge-group-bg); color:var(--ts-badge-group-text); font-size:.55rem; padding:2px 6px; border-radius:12px; line-height:1;}`;
document.head.appendChild(style);

loadAll();
// Groups popover controls: move popover to body when opened to avoid ancestor overflow clipping
if (manageGroupsBtn && groupsPopover) {
  // remember original parent so we can restore on close
  const _popoverOriginalParent = groupsPopover.parentElement;
  const _popoverOriginalNext = groupsPopover.nextSibling;

  function restorePopoverNode() {
    try {
      if (_popoverOriginalParent) {
        // restore only if not already the child
        if (groupsPopover.parentElement !== _popoverOriginalParent) {
          if (_popoverOriginalNext && _popoverOriginalNext.parentElement === _popoverOriginalParent) {
            _popoverOriginalParent.insertBefore(groupsPopover, _popoverOriginalNext);
          } else {
            _popoverOriginalParent.appendChild(groupsPopover);
          }
        }
      }
    } catch (_) { /* best-effort restore */ }
  }

  function closePopover() {
    groupsPopover.classList.remove('show');
    setTimeout(() => { if (!groupsPopover.classList.contains('show')) groupsPopover.style.display = 'none'; }, 140);
    manageGroupsBtn.classList.remove('open');
    manageGroupsBtn.setAttribute('aria-expanded', 'false');
    // restore node back into original place to keep markup tidy
    restorePopoverNode();
    // clear absolute positioning we set when showing
    groupsPopover.style.position = '';
    groupsPopover.style.left = '';
    groupsPopover.style.top = '';
    groupsPopover.style.zIndex = '';
    groupsPopover.style.minWidth = '';
  }

  function showPopoverAtButton() {
    // move popover node to body so it won't be clipped by overflow:hidden ancestors
    try {
      document.body.appendChild(groupsPopover);
      groupsPopover.style.position = 'absolute';
      groupsPopover.style.display = 'block';
      // compute position next to button (below it)
      const rect = manageGroupsBtn.getBoundingClientRect();
      const top = rect.bottom + window.scrollY + 6; // slight gap
      let left = rect.left + window.scrollX;
      // ensure min width matches button or original width
      const minW = Math.max(manageGroupsBtn.offsetWidth, 260);
      groupsPopover.style.minWidth = minW + 'px';
      // clamp to viewport to avoid overflow right edge
      const maxLeft = Math.max(8, window.scrollX + document.documentElement.clientWidth - groupsPopover.offsetWidth - 12);
      if (left > maxLeft) left = maxLeft;
      groupsPopover.style.left = left + 'px';
      groupsPopover.style.top = top + 'px';
      groupsPopover.style.zIndex = 9999;
      // show with animation
      requestAnimationFrame(() => groupsPopover.classList.add('show'));
      manageGroupsBtn.classList.add('open');
      manageGroupsBtn.setAttribute('aria-expanded', 'true');
    } catch (e) {
      // fallback: simply toggle inline display on original node
      groupsPopover.style.display = groupsPopover.style.display === 'block' ? 'none' : 'block';
    }
  }

  manageGroupsBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = groupsPopover.classList.contains('show') || groupsPopover.style.display === 'block';
    if (open) { closePopover(); return; }
    showPopoverAtButton();
  });

  document.addEventListener('click', (e) => {
    if ((groupsPopover.classList.contains('show') || groupsPopover.style.display === 'block') && !groupsPopover.contains(e.target) && e.target !== manageGroupsBtn) {
      closePopover();
    }
  });

  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && (groupsPopover.classList.contains('show') || groupsPopover.style.display === 'block')) { closePopover(); } });
}

// Evidence Dialog Logic (Refined)
const evDlg = document.getElementById('evidence-dialog');
const evClose = document.getElementById('evidence-close');
if (evClose) evClose.addEventListener('click', () => evDlg.close());

function showEvidence(t) {
  if (!evDlg) return;
  const title = document.getElementById('evidence-title');
  const content = document.getElementById('evidence-content');
  if (title) title.textContent = t.name;

  let sections = '';

  const renderVal = (v) => {
    if (v === null || v === undefined) return '<span style="opacity:0.5">null</span>';
    if (typeof v === 'object') {
      const entries = Object.entries(v);
      if (!entries.length) return '{}';
      // Sort keys for consistency
      entries.sort((a, b) => a[0].localeCompare(b[0]));
      return '<div class="ev-obj">' + entries.map(([k, val]) =>
        `<div class="ev-pair"><span class="ev-key">${escapeHtml(k)}:</span><span class="ev-val">${escapeHtml(String(val))}</span></div>`
      ).join('') + '</div>';
    }
    return escapeHtml(String(v));
  };

  const addSec = (label, data) => {
    if (!data) return;
    const items = Array.isArray(data) ? data : [data];
    if (!items.length) return;
    const list = items.map(i => `<li>${renderVal(i)}</li>`).join('');
    sections += `<div class="ev-section"><h5>${label}</h5><ul class="ev-list">${list}</ul></div>`;
  };

  if (t.implied_by && t.implied_by.length) addSec('Implied By', t.implied_by);
  if (t.implies && t.implies.length) addSec('Implies', t.implies);

  const fields = {
    'scripts': 'Scripts', 'headers': 'Headers', 'meta': 'Meta Tags', 'cookies': 'Cookies',
    'website': 'Website Link', 'url': 'URL Pattern', 'html': 'HTML Pattern', 'css': 'CSS',
    'js': 'JavaScript Global', 'dom': 'DOM Selector', 'dns': 'DNS', 'certIssuer': 'Cert Issuer',
    'cpe': 'CPE'
  };

  for (const [key, label] of Object.entries(fields)) {
    addSec(label, t[key]);
  }

  // Generic formatted evidence
  if (t.evidence && t.evidence.length) {
    // Try to parse JSON strings if they look like JSON
    const parsed = t.evidence.map(e => {
      try { return typeof e === 'string' && e.startsWith('{') ? JSON.parse(e) : e; } catch (_) { return e; }
    });
    addSec('Other Evidence', parsed);
  }

  if (!sections) {
    sections = '<div style="padding:2rem; text-align:center; opacity:0.6;"><div style="font-size:2rem; margin-bottom:0.5rem;">🤷‍♂️</div>No detailed evidence available.<br><span style="font-size:0.8rem">Detection might be from basic pattern matching or inferred.</span></div>';
  }

  if (content) content.innerHTML = sections;
  evDlg.showModal();
}
