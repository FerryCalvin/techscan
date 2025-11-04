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

function upsertBarChart(canvas, labels, values, label){
  const ctx = canvas.getContext('2d');
  if (!techChart || canvas.id !== 'techChart'){
    // pass
  }
  const chartRef = canvas.id === 'techChart' ? 'techChart' : 'catChart';
  let existing = chartRef === 'techChart' ? techChart : catChart;
  if (existing){
    existing.data.labels = labels;
    existing.data.datasets[0].data = values;
    existing.update();
    return existing;
  }
  const cfg = {
    type: chartRef === 'techChart' ? 'bar' : 'doughnut',
    data: {
      labels,
      datasets: [{
        label,
        data: values,
        backgroundColor: chartRef === 'techChart' ? '#4e79a7' : [
          '#4e79a7', '#f28e2c', '#e15759', '#76b7b2', '#59a14f',
          '#edc949', '#af7aa1', '#ff9da7', '#9c755f', '#bab0ab'
        ]
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: chartRef !== 'techChart' }
      },
      scales: chartRef === 'techChart' ? { y: { beginAtZero: true } } : {}
    }
  };
  const ch = new Chart(ctx, cfg);
  if (chartRef === 'techChart') techChart = ch; else catChart = ch;
  return ch;
}

async function loadStats(){
  try{
    const data = await fetchJson('/api/stats');
    // fill summary
    document.getElementById('total').textContent = data.scans_total ?? '-';
    const avgDur = data.avg_duration_ms_24h ?? data.avg_duration_ms;
    document.getElementById('avg_duration').textContent = toFixedOrDash(avgDur, 1);
    document.getElementById('avg_tech').textContent = toFixedOrDash(data.avg_tech_count, 2);
    document.getElementById('uptime').textContent = toFixedOrDash(data.uptime_seconds, 0);

    document.getElementById('avg_evidence').textContent = toFixedOrDash(data.avg_evidence_ms_24h ?? data.avg_evidence_ms, 1);
    document.getElementById('avg_va').textContent = toFixedOrDash(data.avg_version_audit_ms_24h ?? data.avg_version_audit_ms, 1);

    // charts
    const techNorm = normalizeTop(data.top_technologies, 'tech', 'tech');
    const catNorm = normalizeTop(data.top_categories, 'category', 'category');

    upsertBarChart(document.getElementById('techChart'), techNorm.labels, techNorm.values, 'Top Technologies');
    upsertBarChart(document.getElementById('catChart'), catNorm.labels, catNorm.values, 'Top Categories');

    // fetch lightweight system health and enrichment counters
    try{
      const h = await fetchJson('/api/system_health');
      const redis = h.redis && h.redis.ok ? '✓' : (h.redis && h.redis.error ? '✖' : '-');
      const db = h.db && h.db.ok ? '✓' : (h.db && h.db.error ? '✖' : '-');
      const queue = h.queue && h.queue.ok ? '✓' : (h.queue && h.queue.error ? '✖' : '-');
      document.getElementById('health-redis').textContent = redis;
      document.getElementById('health-db').textContent = db;
      document.getElementById('health-queue').textContent = queue;
      const mcount = (h.enrichment && h.enrichment.merge_total) ? h.enrichment.merge_total : 0;
      document.getElementById('enrichment-merge-count').textContent = mcount;
    }catch(e){
      // ignore health errors, keep dashboard resilient
    }

  } catch (e){
    console.error('loadStats error', e);
  }
}

window.addEventListener('load', () => {
  loadStats();
  // Auto refresh every 60s
  setInterval(loadStats, 60000);
});
