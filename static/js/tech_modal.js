// tech_modal.js — unified modal controller for tech-cards
(function(){
  try{ console.debug && console.debug('[tech_modal] loaded'); }catch(e){}
  var MODAL_ID = 'tech-modal';
  var OVERLAY_ID = 'tech-modal-overlay';
  var NAME_ID = 'tech-modal-name';
  var SUMMARY_ID = 'tech-modal-summary';
  var EVIDENCE_ID = 'tech-modal-evidence';
  var SITES_LIST_ID = 'tech-modal-sites-list';
  var SITES_PAGER_ID = 'tech-modal-sites-pager';
  var CLOSE_SEL = '#tech-modal-close, [data-action="close"]';
  var EXPORT_SEL = '#tech-modal-export, [data-action="export"], #tech-export-csv';

  function qs(id){ return document.getElementById(id); }
  function qsel(sel, ctx=document){ return ctx.querySelector(sel); }
  function slugify(name){ return (name||'').toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9\-]/g,'').replace(/\-+/g,'-'); }

  // State
  var currentKey = null;
  var currentPage = 0;
  var PAGE_SIZE = 10;
  var prefetchTimers = new WeakMap ? new WeakMap() : new Map();

  function onKeyDown(e){ if(e.key === 'Escape') closeModal(); }
  function openModal(){
    var m = qs(MODAL_ID); var ov = qs(OVERLAY_ID);
    if(!m) return;
    m.classList.add('active'); m.setAttribute('aria-hidden','false');
    if(ov) ov.classList.add('active');
    var closeBtn = qs('tech-modal-close'); if(closeBtn) try{ closeBtn.focus(); }catch(e){}
    document.addEventListener('keydown', onKeyDown);
  }
  function closeModal(){
    var m = qs(MODAL_ID); var ov = qs(OVERLAY_ID);
    if(!m) return;
    m.classList.remove('active'); m.setAttribute('aria-hidden','true');
    if(ov) ov.classList.remove('active');
    document.removeEventListener('keydown', onKeyDown);
  }

  async function fetchTechMeta(key){
    try{ var res = await fetch('/api/tech/' + encodeURIComponent(key)); if(!res.ok) throw new Error(res.status); return await res.json(); }
    catch(e){ console.warn('tech meta fetch error', e); return null; }
  }
  async function fetchSitesPage(key, page){
    var offset = page * PAGE_SIZE;
    try{ var res = await fetch('/api/tech/' + encodeURIComponent(key) + '/sites?limit=' + PAGE_SIZE + '&offset=' + offset + '&sort=recent'); if(!res.ok) throw new Error(res.status); return await res.json(); }
    catch(e){ console.warn('tech sites fetch error', e); return null; }
  }

  function renderMeta(meta){
    var nameEl = qs(NAME_ID); if(nameEl) nameEl.textContent = meta.name || meta.tech_key || '';
    var sum = qs(SUMMARY_ID);
    if(sum){
      sum.innerHTML = '<div class="tech-meta-row"><strong>Detected:</strong> ' + (meta.detected_version || '—') + '</div>' +
                      '<div class="tech-meta-row"><strong>Confidence:</strong> ' + ((meta.confidence||0).toFixed ? (meta.confidence||0).toFixed(2) : (meta.confidence||0)) + '</div>' +
                      '<div class="tech-meta-row"><strong>Total sites:</strong> ' + (meta.counts? meta.counts.total_sites : 0) + '</div>';
    }
    var ev = qs(EVIDENCE_ID); if(ev) ev.innerHTML = '<div class="small-note">Evidence not available in aggregate view.</div>';
  }

  function renderSites(listObj){
    var container = qs(SITES_LIST_ID); var pager = qs(SITES_PAGER_ID);
    if(!container) return; container.innerHTML = '';
    if(!listObj || !Array.isArray(listObj.sites)){ container.textContent = 'No sites available.'; return; }
    listObj.sites.forEach(function(s){
      var li = document.createElement('div'); li.className = 'site-card';
      var last = s.last_scan || '';
      var ver = s.detected_version ? ' • ' + s.detected_version : '';
      li.innerHTML = '<div><a href="/domain/' + encodeURIComponent(s.domain) + '" class="site-link">' + s.domain + '</a><div class="small-note">' + last + ' • tech:' + (s.tech_count||0) + ver + '</div></div>';
      container.appendChild(li);
    });
    if(!pager) return;
    var total = listObj.total || 0; var pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    pager.innerHTML = `<button id="tech-sites-prev">Prev</button><span class="pager-info">Page ${currentPage+1}/${pages}</span><button id="tech-sites-next">Next</button>`;
    var prev = qsel('#tech-sites-prev', pager); var next = qsel('#tech-sites-next', pager);
    if(prev) prev.disabled = currentPage === 0;
    if(next) next.disabled = currentPage >= pages-1;
    if(prev) prev.addEventListener('click', async function(){ if(currentPage>0){ currentPage--; await loadSites(currentKey); } });
    if(next) next.addEventListener('click', async function(){ if(currentPage<pages-1){ currentPage++; await loadSites(currentKey); } });
  }

  async function loadSites(key){ var listObj = await fetchSitesPage(key, currentPage); renderSites(listObj || {sites:[], total:0}); }

  async function showTechModal(key){ currentKey = key; currentPage = 0; var meta = await fetchTechMeta(key) || {}; renderMeta(meta); await loadSites(key); openModal(); }

  async function exportCSV(key){
    try{ var res = await fetch('/api/tech/' + encodeURIComponent(key) + '/sites.csv?limit=2000'); if(!res.ok) throw new Error(res.status); var blob = await res.blob(); var a = document.createElement('a'); var urlObj = URL.createObjectURL(blob); a.href=urlObj; a.download = key + '_sites.csv'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(urlObj); }
    catch(e){ alert('Export failed: '+ (e.message || e)); }
  }

  // Prefetch
  function attachPrefetch(el){
    el.addEventListener('mouseenter', function(){
      var t = setTimeout(async function(){ try{ var nameEl = el.querySelector && el.querySelector('h5'); var name = (nameEl? nameEl.textContent.split('\n')[0] : (el.textContent || '') ).trim() || el.getAttribute('data-tech') || el.getAttribute('data-name'); var key = slugify(name); await fetchTechMeta(key); }catch(e){} }, 300);
      try{ prefetchTimers.set(el, t); }catch(e){ /* noop */ }
    });
    el.addEventListener('mouseleave', function(){ var t = (prefetchTimers.get ? prefetchTimers.get(el) : null); if(t) try{ clearTimeout(t);}catch(e){}; try{ prefetchTimers.delete && prefetchTimers.delete(el); }catch(e){} });
  }

  // Click handler — open modal when tech-card clicked
  document.addEventListener('click', async function(ev){
    var tgt = ev.target || ev.srcElement;
    var card = (tgt && tgt.closest) ? tgt.closest('.tech-card') : null;
    if(!card) return;
    try{ ev.preventDefault(); }catch(e){}
    var name = card.getAttribute('data-tech') || card.getAttribute('data-name');
    if(!name){ var h = card.querySelector && card.querySelector('h5'); if(h) name = (h.textContent.split('\n')[0] || '').replace(/\s*v[0-9].*$/,'').trim(); else name = (card.textContent||'').trim().split('\n')[0]; }
    var key = slugify(name || 'unknown');
    await showTechModal(key);
  });

  // Attach prefetch to existing cards and mutations
  function scanTechCards(){ document.querySelectorAll('.tech-card').forEach(el=> attachPrefetch(el)); }
  var observer = new MutationObserver(scanTechCards);
  observer.observe(document.body, {childList:true, subtree:true});
  scanTechCards();

  // Global handlers: close, export
  document.addEventListener('click', function(ev){
    var tgt = ev.target || ev.srcElement;
    var close = tgt && tgt.closest ? tgt.closest(CLOSE_SEL) : null;
    if(close){ try{ ev.preventDefault(); }catch(e){}; closeModal(); return; }
    var exportBtn = tgt && tgt.closest ? tgt.closest(EXPORT_SEL) : null;
    if(exportBtn){ try{ ev.preventDefault(); }catch(e){}; if(currentKey) exportCSV(currentKey); return; }
  });

  // Overlay click to close
  var overlay = qs(OVERLAY_ID);
  if(overlay) overlay.addEventListener('click', function(e){ if(e.target === overlay) closeModal(); });

}());
