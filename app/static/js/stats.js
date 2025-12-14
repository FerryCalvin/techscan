let techChart = null;
let catChart = null;

function toFixedOrDash(v, d=2){
  if (v === undefined || v === null || Number.isNaN(v)) return '-';
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(d) : '-';
}

function normalizeTop(arr, keyName, labelKey){
  if (!Array.isArray(arr)) return { labels: [], values: [] };
  return {
    labels: arr.map(x => x[labelKey] || x[keyName] || x.name || x.category || x.tech),
    values: arr.map(x => x.count || 0)
  };
}

async function fetchJson(url){
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`fetch ${url} status ${res.status}`);
  return res.json();
}

function ensureCharts(){
  if (!techChart){
    const ctx = document.getElementById('techChart').getContext('2d');
    techChart = new Chart(ctx, {
      type: 'bar',
      data: { labels: [], datasets: [{ label: 'Top Technologies', data: [], backgroundColor: '#4e79a7' }] },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }
  if (!catChart){
    const ctx2 = document.getElementById('catChart').getContext('2d');
    catChart = new Chart(ctx2, {
      type: 'bar',
      data: { labels: [], datasets: [{ label: 'Top Categories', data: [], backgroundColor: '#59a14f' }] },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }
}

function upsertBarChart(canvas, labels, values, label){
  const ctx = canvas.getContext('2d');
  const chartRef = canvas.id === 'techChart' ? 'techChart' : 'catChart';
  let existing = chartRef === 'techChart' ? techChart : catChart;
  if (existing){
    existing.data.labels = labels;
    existing.data.datasets[0].data = values;
    existing.update();
    return existing;
  }
  const cfg = {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label,
        data: values,
        backgroundColor: chartRef === 'techChart' ? '#4e79a7' : '#59a14f'
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true } }
    }
  };
  const ch = new Chart(ctx, cfg);
  if (chartRef === 'techChart') techChart = ch; else catChart = ch;
  return ch;
}

function formatDuration(seconds){
  const s = Number(seconds || 0);
  if (!Number.isFinite(s) || s <= 0) return '-';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

async function loadStats(){
  try{
    // Loading state
    const loading = document.getElementById('loading');
    const errEl = document.getElementById('error');
    if (loading) loading.style.display = 'block';
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }

    ensureCharts();
    const data = await fetchJson('/api/stats');
    // fill summary
    document.getElementById('total').textContent = data.scans_total ?? '-';
    const avgDurMs = data.avg_duration_ms_24h ?? data.avg_duration_ms;
    const avgDurSeconds = Number(avgDurMs) / 1000;
    let avgDurText = '-';
    if (Number.isFinite(avgDurSeconds) && avgDurSeconds > 0){
      const formatted = toFixedOrDash(avgDurSeconds, 2);
      avgDurText = formatted === '-' ? '-' : `${formatted} s`;
    }
    document.getElementById('avg_duration').textContent = avgDurText;
    document.getElementById('avg_tech').textContent = toFixedOrDash(data.avg_tech_count, 2);
    document.getElementById('uptime').textContent = formatDuration(data.uptime_seconds);

    document.getElementById('avg_evidence').textContent = toFixedOrDash(data.avg_evidence_ms_24h ?? data.avg_evidence_ms, 1);
    document.getElementById('avg_va').textContent = toFixedOrDash(data.avg_version_audit_ms_24h ?? data.avg_version_audit_ms, 1);

    // last scan time formatting
    const lastScanEl = document.getElementById('last_scan');
    if (lastScanEl){
      let ts = null;
      if (data.last_scan){
        if (typeof data.last_scan === 'number') ts = data.last_scan;
        else if (typeof data.last_scan === 'string') ts = Date.parse(data.last_scan)/1000;
        else if (data.last_scan.finished_at) ts = data.last_scan.finished_at;
      }
      if (ts){
        const d = new Date(Number(ts) * 1000);
        lastScanEl.textContent = d.toLocaleString();
      } else {
        lastScanEl.textContent = '-';
      }
    }

    // charts
    const techNorm = normalizeTop(data.top_technologies, 'tech', 'tech');
    const catNorm = normalizeTop(data.top_categories, 'category', 'category');

    upsertBarChart(document.getElementById('techChart'), techNorm.labels, techNorm.values, 'Top Technologies');
    upsertBarChart(document.getElementById('catChart'), catNorm.labels, catNorm.values, 'Top Categories');

  } catch (e){
    console.error('loadStats error', e);
    const errEl = document.getElementById('error');
    if (errEl){
      errEl.textContent = `Failed to load stats: ${e?.message || e}`;
      errEl.style.display = 'block';
    }
  } finally {
    const loading = document.getElementById('loading');
    if (loading) loading.style.display = 'none';
  }
}

window.addEventListener('load', () => {
  loadStats();
  // Auto refresh every 60s
  setInterval(loadStats, 60000);
});
