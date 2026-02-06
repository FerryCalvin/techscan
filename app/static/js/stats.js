/**
 * TechScan Stats Dashboard Logic
 */

(function loadChartJs() {
  const LOCAL_SRC = window.TECHSCAN_CONFIG.CHART_JS_LOCAL;
  const CDN_SRC = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js';
  const head = document.head || document.getElementsByTagName('head')[0];
  let isLoaded = false;
  let fallbackQueued = false;

  function markLoaded(origin) {
    const hasChart = typeof window.Chart !== 'undefined';
    if (origin === 'local' && !hasChart) {
      if (!fallbackQueued) {
        fallbackQueued = true;
        console.warn('[stats] Local Chart.js loaded but window.Chart missing; attempting CDN fallback.');
        inject(CDN_SRC, 'cdn');
      }
      return;
    }
    if (!hasChart) {
      if (origin === 'cdn') {
        console.error('[stats] Chart.js CDN loaded but window.Chart still undefined.');
        isLoaded = true; // prevent infinite retry loop
      }
      return;
    }
    if (isLoaded) return;
    isLoaded = true;
    window.__chartJsOrigin = origin;
    window.dispatchEvent(new Event('chartjs:ready'));
  }

  function inject(src, origin) {
    if (isLoaded) return null;
    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.onload = () => markLoaded(origin);
    script.onerror = () => {
      if (origin === 'local' && !fallbackQueued) {
        fallbackQueued = true;
        console.warn('[stats] Local Chart.js failed; attempting CDN fallback.');
        inject(CDN_SRC, 'cdn');
      } else if (origin === 'cdn') {
        console.error('[stats] Chart.js failed to load from both local bundle and CDN fallback.');
      }
    };
    head.appendChild(script);
    return script;
  }

  inject(LOCAL_SRC, 'local');

  setTimeout(() => {
    if (typeof window.Chart !== 'undefined') { return; }
    if (!fallbackQueued) {
      fallbackQueued = true;
      console.warn('[stats] Chart.js still unavailable; attempting CDN fallback.');
      inject(CDN_SRC, 'cdn');
    }
  }, 5000);
})();

const CATEGORY_TITLE_OVERRIDES = {
  // JavaScript
  'javascript libraries': 'JavaScript Libraries',
  'javascript library': 'JavaScript Libraries',
  'js libraries': 'JavaScript Libraries',
  'javascript frameworks': 'JavaScript Frameworks',
  'javascript framework': 'JavaScript Frameworks',
  'js frameworks': 'JavaScript Frameworks',
  'js framework': 'JavaScript Frameworks',

  // Web Frameworks
  'web frameworks': 'Web Frameworks',
  'web framework': 'Web Frameworks',
  'frameworks': 'Web Frameworks',

  // UI/CSS
  'ui frameworks': 'UI Frameworks',
  'ui framework': 'UI Frameworks',
  'css frameworks': 'CSS Frameworks',
  'css framework': 'CSS Frameworks',
  'css': 'CSS Frameworks',

  // CMS
  'content management system': 'CMS',
  'content management systems': 'CMS',
  'content management': 'CMS',
  'cms': 'CMS',

  // Programming Languages
  'programming languages': 'Programming Languages',
  'programming language': 'Programming Languages',
  'languages': 'Programming Languages',

  // E-commerce
  'e-commerce': 'E-commerce',
  'ecommerce': 'E-commerce',
  'e-commerce platforms': 'E-commerce',
  'ecommerce platforms': 'E-commerce',

  // Analytics
  'analytics': 'Analytics',
  'web analytics': 'Analytics',
  'site analytics': 'Analytics',

  // Tag Managers
  'tag managers': 'Tag Managers',
  'tag manager': 'Tag Managers',

  // CDN
  'cdn': 'CDN',
  'cdn providers': 'CDN',
  'content delivery network': 'CDN',

  // Web Servers
  'web servers': 'Web Servers',
  'web server': 'Web Servers',
  'servers': 'Web Servers',

  // JavaScript Runtimes
  'javascript runtimes': 'JavaScript Runtimes',
  'javascript runtime': 'JavaScript Runtimes',
  'js runtimes': 'JavaScript Runtimes',
  'runtime': 'JavaScript Runtimes',

  // Reverse Proxies
  'reverse proxies': 'Reverse Proxies',
  'reverse proxy': 'Reverse Proxies',

  // Databases
  'databases': 'Databases',
  'database': 'Databases',
  'database management': 'Databases',

  // Security
  'security': 'Security',
  'ssl/tls certificate authorities': 'Security',
  'ssl': 'Security',

  // SEO
  'seo': 'SEO',
  'search engine optimization': 'SEO',

  // WordPress
  'wordpress plugins': 'WordPress Plugins',
  'wordpress plugin': 'WordPress Plugins',
  'wordpress themes': 'WordPress Themes',
  'wordpress theme': 'WordPress Themes',

  // Font/Icons
  'font scripts': 'Font Scripts',
  'icon sets': 'Icon Sets',
  'fonts': 'Font Scripts',
  'icons': 'Icon Sets',

  // Marketing
  'marketing automation': 'Marketing Automation',
  'marketing': 'Marketing Automation',
  'advertising': 'Advertising',
  'a/b testing': 'A/B Testing',

  // Miscellaneous
  'miscellaneous': 'Miscellaneous',
  'misc': 'Miscellaneous',
  'other': 'Miscellaneous',

  // Hosting
  'hosting': 'Hosting',
  'hosting services': 'Hosting',
  'paas': 'Hosting',

  // Live Chat
  'live chat': 'Live Chat',
  'chat': 'Live Chat',

  // Video
  'video players': 'Video Players',
  'video': 'Video Players',

  // Rich Text
  'rich text editors': 'Rich Text Editors',
  'text editors': 'Rich Text Editors',

  // PWA
  'progressive web apps': 'Progressive Web Apps',
  'pwa': 'Progressive Web Apps'
};

const CATEGORY_UPPER_TOKENS = new Set(['api', 'cdn', 'cms', 'css', 'dns', 'erp', 'http', 'https', 'id', 'pdf', 'php', 'redis', 'rest', 'seo', 'sql', 'ssl', 'tls', 'ui', 'ux']);

function buildTimeseriesFallback() {
  const hours = [];
  const now = new Date();
  for (let i = 11; i >= 0; i--) {
    const slot = new Date(now.getTime() - i * 60 * 60 * 1000);
    const hourVal = slot.getHours();
    hours.push(`${hourVal.toString().padStart(2, '0')}:00`);
  }
  const sampleScans = [18, 22, 27, 31, 36, 42, 45, 40, 34, 30, 26, 22];
  const sampleConfidence = [83.2, 83.9, 84.6, 85.1, 85.8, 86.3, 86.6, 86.2, 85.7, 85.1, 84.6, 84.0];
  return {
    timestamps: hours,
    scans: sampleScans.slice(0, hours.length),
    avg_conf: sampleConfidence.slice(0, hours.length),
    success: 820,
    timeout: 145,
    error: 35
  };
}

function normalizeTimeseries(raw) {
  const fallback = buildTimeseriesFallback();
  if (!raw || typeof raw !== 'object') {
    return fallback;
  }
  const toArray = (value) => Array.isArray(value) ? value.slice() : [];
  let timestamps = toArray(raw.timestamps).map(v => String(v || '').trim()).filter(Boolean);
  if (!timestamps.length) {
    timestamps = fallback.timestamps.slice();
  }
  let scans = toArray(raw.scans).map(v => Number(v)).filter(v => Number.isFinite(v));
  if (!scans.length) {
    scans = fallback.scans.slice();
  }
  if (scans.length !== timestamps.length) {
    const len = Math.min(scans.length, timestamps.length);
    if (len === 0) {
      timestamps = fallback.timestamps.slice();
      scans = fallback.scans.slice();
    } else {
      timestamps = timestamps.slice(-len);
      scans = scans.slice(-len);
    }
  }
  let avgConf = toArray(raw.avg_conf).map(v => Number(v)).filter(v => Number.isFinite(v));
  if (!avgConf.length) {
    avgConf = fallback.avg_conf.slice(0, timestamps.length);
  }
  if (avgConf.length > timestamps.length) {
    avgConf = avgConf.slice(-timestamps.length);
  } else if (avgConf.length < timestamps.length) {
    const missing = timestamps.length - avgConf.length;
    const lastVal = avgConf.length ? avgConf[avgConf.length - 1] : fallback.avg_conf[0];
    for (let i = 0; i < missing; i++) {
      avgConf.push(lastVal);
    }
  }
  const toNumber = (value, fallbackValue) => {
    const num = Number(value);
    return Number.isFinite(num) && num >= 0 ? num : fallbackValue;
  };
  return {
    timestamps,
    scans,
    avg_conf: avgConf,
    success: toNumber(raw.success, fallback.success),
    timeout: toNumber(raw.timeout, fallback.timeout),
    error: toNumber(raw.error, fallback.error)
  };
}

window._lastTimeseries = window._lastTimeseries || buildTimeseriesFallback();
window._topTechUsageTotal = window._topTechUsageTotal || 0;

let chartWarningIssued = false;
function ensureChartLib() {
  if (typeof window.Chart === 'undefined') {
    if (!chartWarningIssued) {
      console.warn('[stats] Chart.js is not loaded; chart rendering skipped.');
      chartWarningIssued = true;
    }
    return false;
  }
  return true;
}

function whenChartReady(callback) {
  if (typeof window.Chart !== 'undefined') {
    callback();
    return;
  }
  const handler = () => {
    window.removeEventListener('chartjs:ready', handler);
    callback();
  };
  window.addEventListener('chartjs:ready', handler);
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

function normalizeCategoryKey(label) {
  if (label === undefined || label === null) return '';
  const lowered = String(label).trim().toLowerCase();
  // Check if there's an override - if so, return the canonical form's key
  const override = CATEGORY_TITLE_OVERRIDES[lowered];
  if (override) {
    // Return the lowercase of the canonical form for consistent grouping
    return override.toLowerCase();
  }
  return lowered;
}

function formatCategoryLabel(label) {
  if (label === undefined || label === null) return '';
  const trimmed = String(label).replace(/\s+/g, ' ').trim();
  if (!trimmed) return '';
  const override = CATEGORY_TITLE_OVERRIDES[normalizeCategoryKey(trimmed)];
  if (override) return override;
  const words = trimmed.toLowerCase().split(' ');
  const formatted = words.map(word => {
    if (CATEGORY_UPPER_TOKENS.has(word)) return word.toUpperCase();
    if (word.length <= 2) return word.toUpperCase();
    return word.charAt(0).toUpperCase() + word.slice(1);
  });
  return formatted.join(' ');
}

function formatBytes(value) {
  if (value === null || value === undefined) return '';
  let bytes = Number(value);
  if (!Number.isFinite(bytes)) return '';
  if (bytes < 0) return '';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unitIndex = 0;
  while (bytes >= 1024 && unitIndex < units.length - 1) {
    bytes /= 1024;
    unitIndex += 1;
  }
  const precision = bytes >= 10 ? 1 : 2;
  return `${bytes.toFixed(precision)} ${units[unitIndex]}`;
}

function updatePayloadMetric(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    el.textContent = '–';
    el.removeAttribute('title');
    return;
  }
  const formatted = formatBytes(value);
  if (formatted) {
    el.textContent = formatted;
    el.title = `${Math.round(Number(value))} bytes`;
  } else {
    el.textContent = '0 B';
    el.title = '';
  }
}

function normalizeCategories(raw) {
  if (!raw) return [];
  let values = [];
  if (Array.isArray(raw)) {
    values = raw.flatMap(item => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object') {
        if (typeof item.name === 'string') return item.name;
        if (typeof item.category === 'string') return item.category;
        return Object.values(item).filter(v => typeof v === 'string');
      }
      return [];
    });
  } else if (typeof raw === 'string') {
    values = raw.split(',');
  } else if (typeof raw === 'object') {
    if (typeof raw.name === 'string') {
      values = [raw.name];
    } else if (typeof raw.category === 'string') {
      values = [raw.category];
    } else {
      values = Object.values(raw).filter(v => typeof v === 'string');
    }
  }
  const normalized = values
    .map(v => formatCategoryLabel(v))
    .filter(Boolean);
  return normalized.filter((val, idx) => normalized.indexOf(val) === idx);
}

const UNCATEGORIZED_LABEL = 'Uncategorized';

// Fallback categories for common technologies missing categories in database
const TECH_CATEGORY_FALLBACK = {
  // JavaScript Libraries
  'jquery': 'JavaScript Libraries',
  'jquery ui': 'JavaScript Libraries',
  'jquery migrate': 'JavaScript Libraries',
  'jquery cdn': 'JavaScript Libraries',
  'react': 'JavaScript Libraries',
  'vue.js': 'JavaScript Libraries',
  'angular': 'JavaScript Frameworks',
  'angularjs': 'JavaScript Frameworks',
  'alpine.js': 'JavaScript Libraries',
  'moment.js': 'JavaScript Libraries',
  'lodash': 'JavaScript Libraries',
  'underscore.js': 'JavaScript Libraries',
  'axios': 'JavaScript Libraries',
  'core-js': 'JavaScript Libraries',
  'swiper': 'JavaScript Libraries',
  'slick': 'JavaScript Libraries',
  'owl carousel': 'JavaScript Libraries',
  'datatables': 'JavaScript Libraries',
  'marked': 'JavaScript Libraries',
  'highlight.js': 'JavaScript Libraries',
  'prism': 'JavaScript Libraries',
  'popper': 'JavaScript Libraries',
  'popper.js': 'JavaScript Libraries',

  // JavaScript Frameworks (NOT just libraries, NOT web servers, NOT programming languages)
  'next.js': 'JavaScript Frameworks',
  'nuxt.js': 'JavaScript Frameworks',
  'nuxt': 'JavaScript Frameworks',
  'gatsby': 'JavaScript Frameworks',
  'svelte': 'JavaScript Frameworks',
  'sveltekit': 'JavaScript Frameworks',
  'remix': 'JavaScript Frameworks',
  'solid': 'JavaScript Frameworks',
  'astro': 'JavaScript Frameworks',
  'express': 'JavaScript Frameworks',
  'express.js': 'JavaScript Frameworks',
  'koa': 'JavaScript Frameworks',
  'fastify': 'JavaScript Frameworks',
  'hapi': 'JavaScript Frameworks',
  'nest.js': 'JavaScript Frameworks',
  'nestjs': 'JavaScript Frameworks',
  'adonis': 'JavaScript Frameworks',
  'meteor': 'JavaScript Frameworks',
  'ember.js': 'JavaScript Frameworks',
  'ember': 'JavaScript Frameworks',
  'backbone.js': 'JavaScript Libraries',
  'backbone': 'JavaScript Libraries',
  'knockout.js': 'JavaScript Libraries',
  'knockout': 'JavaScript Libraries',
  'polymer': 'JavaScript Libraries',
  'lit': 'JavaScript Libraries',
  'preact': 'JavaScript Libraries',
  'inferno': 'JavaScript Libraries',
  'mithril': 'JavaScript Libraries',
  'htmx': 'JavaScript Libraries',
  'stimulus': 'JavaScript Libraries',
  'turbo': 'JavaScript Libraries',
  'hotwire': 'JavaScript Libraries',

  // UI/CSS Frameworks
  'bootstrap': 'UI Frameworks',
  'tailwind css': 'CSS Frameworks',
  'foundation': 'UI Frameworks',
  'bulma': 'CSS Frameworks',
  'materialize css': 'UI Frameworks',
  'semantic ui': 'UI Frameworks',

  // Font/Icons
  'font awesome': 'Font Scripts',
  'google font api': 'Font Scripts',
  'material icons': 'Font Scripts',
  'bootstrap icons': 'Font Scripts',
  'feather icons': 'Icon Sets',
  'ionicons': 'Icon Sets',

  // WordPress
  'wpml': 'WordPress Plugins',
  'wordpress multilingual plugin (wpml)': 'WordPress Plugins',
  'slider revolution': 'WordPress Plugins',
  'elementor': 'WordPress Plugins',
  'yoast seo': 'WordPress Plugins',
  'contact form 7': 'WordPress Plugins',
  'woocommerce': 'E-commerce',

  // Security
  'sucuri': 'Security',
  'bitninja': 'Security',
  'imunify360': 'Security',
  'imunify360-webshield': 'Security',
  'cloudflare': 'CDN',

  // Analytics/Marketing
  'google analytics': 'Analytics',
  'google tag manager': 'Tag Managers',
  'facebook pixel': 'Advertising',
  'hotjar': 'Analytics',
  'tableau': 'Analytics',

  // Servers
  'nginx': 'Web Servers',
  'apache': 'Web Servers',
  'apache http server': 'Web Servers',
  'litespeed': 'Web Servers',
  'tengine': 'Web Servers',
  'iis': 'Web Servers',
  'microsoft iis': 'Web Servers',
  'caddy': 'Web Servers',

  // Operating Systems
  'ubuntu': 'Operating Systems',
  'debian': 'Operating Systems',
  'centos': 'Operating Systems',
  'windows server': 'Operating Systems',
  'freebsd': 'Operating Systems',

  // Programming Languages (actual languages only)
  'php': 'Programming Languages',
  'python': 'Programming Languages',
  'ruby': 'Programming Languages',
  'java': 'Programming Languages',
  'c#': 'Programming Languages',
  'perl': 'Programming Languages',
  'lua': 'Programming Languages',

  // JavaScript Runtimes (NOT programming languages)
  'node.js': 'JavaScript Runtimes',
  'deno': 'JavaScript Runtimes',
  'bun': 'JavaScript Runtimes',

  // Build Tools & Transpilers
  'typescript': 'JavaScript Libraries',
  'babel': 'JavaScript Libraries',
  'webpack': 'JavaScript Libraries',
  'vite': 'JavaScript Libraries',
  'esbuild': 'JavaScript Libraries',
  'parcel': 'JavaScript Libraries',
  'rollup': 'JavaScript Libraries',
  'go': 'Programming Languages',

  // CMS
  'wordpress': 'CMS',
  'joomla': 'CMS',
  'drupal': 'CMS',
  'magento': 'E-commerce',
  'shopify': 'E-commerce',

  // Databases
  'mysql': 'Databases',
  'postgresql': 'Databases',
  'mongodb': 'Databases',
  'redis': 'Databases',

  // Video
  'youtube': 'Video Players',
  'vimeo': 'Video Players',
  'video.js': 'Video Players',

  // Other common
  'esf': 'Security',
  'ghs': 'Hosting',
  'awselb': 'Load Balancers',
  'bakso': 'Miscellaneous'
};

// Helper: check if a technology name has a known fallback category
function hasFallbackCategory(techName) {
  if (!techName) return false;
  return !!TECH_CATEGORY_FALLBACK[String(techName).toLowerCase()];
}

// Helper: get fallback category for a technology
function getFallbackCategory(techName) {
  if (!techName) return null;
  return TECH_CATEGORY_FALLBACK[String(techName).toLowerCase()] || null;
}

let techModalDomains = [];
let categoryChartInstance = null;
let categoryPieCharts = {};
let throughputChartInstance = null;
let resultPieInstance = null;
let uptimeInterval = null;

function makeBarChart(canvasId, labels, data, barColor) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !ensureChartLib()) return null;

  // Make sure we have at least 'something' to show if empty (unlikely given upstream checks)
  const chartLabels = (labels && labels.length) ? labels : ['No Usage'];
  const chartData = (data && data.length) ? data : [0];

  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: chartLabels,
      datasets: [{
        label: 'Count',
        data: chartData,
        backgroundColor: barColor || '#60a5fa',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: document.body.classList.contains('light') ? 'rgba(255,255,255,0.95)' : 'rgba(0,0,0,0.8)',
          titleColor: document.body.classList.contains('light') ? '#0f172a' : '#fff',
          bodyColor: document.body.classList.contains('light') ? '#334155' : '#fff',
          borderColor: document.body.classList.contains('light') ? '#e2e8f0' : 'transparent',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          ticks: { color: document.body.classList.contains('light') ? '#64748b' : 'rgba(255,255,255,0.7)' },
          grid: { color: document.body.classList.contains('light') ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.1)' },
          beginAtZero: true
        },
        y: {
          ticks: { color: document.body.classList.contains('light') ? '#475569' : 'rgba(255,255,255,0.9)' },
          grid: { display: false }
        }
      }
    }
  });

  // Track instance for theme updates
  if (canvasId === 'throughputChart') throughputChartInstance = newChart;
  else if (canvasId === 'resultPie') resultPieInstance = newChart;
  else if (String(canvasId).startsWith('cat-pie-')) categoryPieCharts[canvasId] = newChart;

  return newChart;
}

// Global theme listener for dynamic chart updates
document.addEventListener('DOMContentLoaded', () => {
  const themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      // Allow time for class toggle
      setTimeout(updateAllChartsTheme, 50);
    });
  }
});

function updateAllChartsTheme() {
  const isLight = document.body.classList.contains('light');
  const textColor = isLight ? '#0f172a' : '#fff';
  const tickColor = isLight ? '#64748b' : 'rgba(255,255,255,0.7)';
  const gridColor = isLight ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.1)';
  const tooltipBg = isLight ? 'rgba(255,255,255,0.95)' : 'rgba(0,0,0,0.8)';
  const tooltipText = isLight ? '#0f172a' : '#fff';
  const tooltipBorder = isLight ? '#e2e8f0' : 'transparent';
  const borderColor = isLight ? '#fff' : 'rgba(255,255,255,0.1)';

  const chartsToUpdate = [
    throughputChartInstance,
    resultPieInstance,
    categoryChartInstance,
    ...Object.values(categoryPieCharts)
  ];

  chartsToUpdate.forEach(chart => {
    if (!chart) return;

    // Update scales if exist
    if (chart.options.scales) {
      ['x', 'y'].forEach(axis => {
        if (chart.options.scales[axis]) {
          if (chart.options.scales[axis].ticks) chart.options.scales[axis].ticks.color = tickColor;
          if (chart.options.scales[axis].grid) chart.options.scales[axis].grid.color = gridColor;
        }
      });
    }

    // Update plugins
    if (chart.options.plugins) {
      if (chart.options.plugins.legend && chart.options.plugins.legend.labels) {
        chart.options.plugins.legend.labels.color = textColor;
      }
      if (chart.options.plugins.tooltip) {
        chart.options.plugins.tooltip.backgroundColor = tooltipBg;
        chart.options.plugins.tooltip.titleColor = tooltipText;
        chart.options.plugins.tooltip.bodyColor = tooltipText;
        chart.options.plugins.tooltip.borderColor = tooltipBorder;
        chart.options.plugins.tooltip.borderWidth = 1;
      }
      if (chart.options.plugins.datalabels) {
        chart.options.plugins.datalabels.color = textColor;
      }
    }

    // Update datasets border (doughnuts)
    if (chart.data.datasets) {
      chart.data.datasets.forEach(ds => {
        if (ds.borderColor && typeof ds.borderColor === 'string') {
          // Only update neutral borders, keep specific colored borders if any (usually simple charts use neutral)
          // For donuts we used neutral borders
          if (ds.borderColor === 'rgba(255,255,255,0.1)' || ds.borderColor === '#fff') {
            ds.borderColor = borderColor;
          }
        }
      });
    }

    chart.update();
  });
}


function updateUptime(seconds) {
  // Removed live counting for simplicity unless restored in future
}

// ♻️ FETCH MAIN DATA
async function fetchStats() {
  try {
    const res = await fetch(`/api/stats?t=${Date.now()}`);
    if (!res.ok) throw new Error('Stats fetch failed');
    const data = await res.json();

    // -- 1. Mini Cards --
    document.getElementById('total-scans').textContent = (data.scans || 0).toLocaleString('en-US');
    document.getElementById('total-domains').textContent = (data.unique_domains || 0).toLocaleString('en-US');
    updatePayloadMetric('total-payload', data.total_payload_bytes);

    const avgDur = parseFloat(data.avg_duration_ms_recent || 0);
    document.getElementById('avg-duration').textContent = (avgDur / 1000).toFixed(2);

    const upSec = parseFloat(data.uptime_seconds || 0);
    const hrs = Math.floor(upSec / 3600);
    const mins = Math.floor((upSec % 3600) / 60);
    document.getElementById('uptime').textContent = `${hrs}h ${mins}m`;

    if (data.last_scan_ts) {
      const d = new Date(data.last_scan_ts * 1000);
      document.getElementById('last-scan').textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    } else {
      document.getElementById('last-scan').textContent = 'None';
    }

    // -- System Health Indicators --
    const redisEl = document.getElementById('redis-status');
    if (redisEl) {
      const rUp = !!data.redis_alive;
      redisEl.textContent = rUp ? 'Redis: OK' : 'Redis: DOWN';
      redisEl.style.backgroundColor = rUp ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)';
      redisEl.style.color = rUp ? '#4ade80' : '#f87171';
      redisEl.style.border = rUp ? '1px solid rgba(34,197,94,0.3)' : '1px solid rgba(239,68,68,0.3)';
    }

    const dbEl = document.getElementById('db-status');
    if (dbEl) {
      const dUp = !!data.db_alive;
      dbEl.textContent = dUp ? 'DB: OK' : 'DB: DOWN';
      dbEl.style.backgroundColor = dUp ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)';
      dbEl.style.color = dUp ? '#4ade80' : '#f87171';
      dbEl.style.border = dUp ? '1px solid rgba(34,197,94,0.3)' : '1px solid rgba(239,68,68,0.3)';
    }

    const qEl = document.getElementById('queue-status');
    if (qEl) {
      // Basic heuristic: check if queue_size is returned
      const qOk = (data.queue_size !== undefined && data.queue_size !== null);
      qEl.textContent = qOk ? `Queue: ${data.queue_size}` : 'Queue: -';
      qEl.style.backgroundColor = 'rgba(56,189,248,0.15)';
      qEl.style.color = '#38bdf8';
      qEl.style.border = '1px solid rgba(56,189,248,0.3)';
    }

    // -- Payload Footprint Averages --
    if (data.payload_stats) {
      updatePayloadMetric('payload-daily', data.payload_stats.avg_24h);
      updatePayloadMetric('payload-weekly', data.payload_stats.avg_7d);
      updatePayloadMetric('payload-monthly', data.payload_stats.avg_30d);
    }

    // -- 2. Charts (Timeseries & Pie) --
    // Normalize timeseries data
    const ts = normalizeTimeseries(data.timeseries);
    window._lastTimeseries = ts;

    // Confidence
    const avgConfVal = ts.avg_conf && ts.avg_conf.length
      ? (ts.avg_conf.reduce((a, b) => a + b, 0) / ts.avg_conf.length)
      : 0;
    document.getElementById('confidence-value').textContent = avgConfVal.toFixed(1) + '%';


    // -- Wait for Chart.js --
    whenChartReady(() => {
      // A) Throughput Chart
      const ctxTP = document.getElementById('throughputChart');
      if (ctxTP) {
        if (throughputChartInstance) throughputChartInstance.destroy();

        // Create fill gradient
        const tCtx = ctxTP.getContext('2d');
        const gradient = tCtx.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(52, 211, 153, 0.4)');
        gradient.addColorStop(1, 'rgba(52, 211, 153, 0)');

        throughputChartInstance = new Chart(ctxTP, {
          type: 'line',
          data: {
            labels: ts.timestamps,
            datasets: [{
              label: 'Scans/Hr',
              data: ts.scans,
              borderColor: '#34d399',
              backgroundColor: gradient,
              fill: true,
              tension: 0.4,
              pointBackgroundColor: '#10b981',
              pointRadius: 3
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: document.body.classList.contains('light') ? 'rgba(255,255,255,0.95)' : 'rgba(0,0,0,0.8)',
                titleColor: document.body.classList.contains('light') ? '#0f172a' : '#fff',
                bodyColor: document.body.classList.contains('light') ? '#334155' : '#fff',
                borderColor: document.body.classList.contains('light') ? '#e2e8f0' : 'transparent',
                borderWidth: 1
              }
            },
            scales: {
              x: {
                ticks: { color: document.body.classList.contains('light') ? '#64748b' : 'rgba(255,255,255,0.7)', font: { size: 10 } },
                grid: { display: false }
              },
              y: {
                ticks: { color: document.body.classList.contains('light') ? '#475569' : 'rgba(255,255,255,0.7)', font: { size: 10 } },
                grid: { color: document.body.classList.contains('light') ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.1)' },
                beginAtZero: true
              }
            }
          }
        });
      }

      // B) Result Breakdown Pie
      const ctxPie = document.getElementById('resultPie');
      if (ctxPie) {
        if (resultPieInstance) resultPieInstance.destroy();
        const pSuccess = ts.success;
        const pTimeout = ts.timeout;
        const pError = ts.error;
        const totalRez = pSuccess + pTimeout + pError;

        // If all zero, show empty placeholder or keep empty
        if (totalRez > 0) {
          resultPieInstance = new Chart(ctxPie, {
            type: 'doughnut',
            data: {
              labels: ['Success', 'Timeout', 'Error'],
              datasets: [{
                data: [pSuccess, pTimeout, pError],
                backgroundColor: ['#10b981', '#fbbf24', '#f87171'],
                borderColor: document.body.classList.contains('light') ? '#fff' : 'rgba(255,255,255,0.1)',
                borderWidth: 2
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'right',
                  labels: {
                    color: document.body.classList.contains('light') ? '#334155' : '#fff',
                    font: { size: 10 }
                  }
                }
              }
            }
          });
        }
      }
    });

    // -- 3. Top Tech List --
    const techBody = document.getElementById('top-tech-body');
    if (techBody && data.top_techs) {
      techBody.innerHTML = '';
      data.top_techs.forEach((t, i) => {
        const cat = Array.isArray(t.category) ? t.category.join(', ')
          : (typeof t.category === 'string' && t.category.trim() !== '' ? t.category : (getFallbackCategory(t.tech) || '-'));
        const row = document.createElement('tr');
        row.innerHTML = `
          <td class="table-index">${i + 1}</td>
          <td style="font-weight:600;color:#e2e8f0;">${t.tech}</td>
          <td class="table-category">${cat}</td>
          <td style="text-align:right;font-weight:600;color:#60a5fa;">${t.count}</td>
        `;
        row.addEventListener('click', () => openTechModal(t.tech));
        techBody.appendChild(row);
      });
    }

    // -- 4. Top Category List --
    const cBody = document.getElementById('top-cat-body');
    if (cBody && data.top_categories) {
      cBody.innerHTML = '';
      data.top_categories.forEach((c, i) => {
        const row = document.createElement('tr');
        const catName = formatCategoryLabel(c.category);
        row.innerHTML = `
          <td class="table-index">${i + 1}</td>
          <td style="font-weight:600;color:#e2e8f0;">${catName}</td>
          <td style="text-align:right;font-weight:600;color:#60a5fa;">${c.count}</td>
        `;
        row.addEventListener('click', () => openCategoryModal(c.category));
        cBody.appendChild(row);
      });
    }

    // -- 5. Render classification donut carousel --
    // We pass top categories specifically for classification
    // (Ensure we have enough data to render meaningless charts)
    if (data.top_categories && data.top_categories.length > 0) {
      renderCategoryClassification(data.top_categories);
    } else {
      document.getElementById('category-charts-container').innerHTML = '<div class="loading-text" style="padding:1rem;">No category data</div>';
    }

  } catch (err) {
    console.error('Stats fetch error:', err);
  }
}

function iconColorFor(name) {
  if (!name) return '#ccc';
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
  return '#' + '00000'.substring(0, 6 - c.length) + c;
}

async function openTechModal(techName) {
  const modal = document.getElementById('techModal');
  modal.classList.remove('hidden');

  // Update Tech Icon
  const iconImg = document.getElementById('modal-tech-icon');
  const iconContainer = iconImg ? iconImg.parentElement : null;

  // Remove existing fallback if any
  if (iconContainer) {
    const fallback = iconContainer.querySelector('.tech-icon-fallback');
    if (fallback) fallback.remove();
  }

  if (iconImg) {
    iconImg.style.display = 'none'; // Reset to hidden
    // Normalize tech name to match icon filename
    // Allow + and # for C++, C#
    let iconKey = techName.toLowerCase().replace(/[^a-z0-9+#]/g, '');

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
      'elasticsearch': 'elastic',
      'tailwind': 'tailwindcss', 'tailwind css': 'tailwindcss'
    };

    if (iconMap[techName.toLowerCase()]) {
      iconKey = iconMap[techName.toLowerCase()];
    } else if (iconMap[iconKey]) {
      iconKey = iconMap[iconKey];
    }

    iconImg.src = `/static/icons/tech/${encodeURIComponent(iconKey)}.svg`;
    iconImg.onload = function () {
      this.style.display = 'block';
    };
    iconImg.onerror = function () {
      this.style.display = 'none';
      if (iconContainer) {
        const letter = techName.charAt(0).toUpperCase();
        const color = iconColorFor(techName);
        const fallback = document.createElement('div');
        fallback.className = 'tech-icon-fallback tech-icon-large';
        fallback.style.backgroundColor = color;
        fallback.style.display = 'flex';
        fallback.style.alignItems = 'center';
        fallback.style.justifyContent = 'center';
        fallback.style.color = 'white';
        fallback.style.fontWeight = 'bold';
        fallback.style.fontSize = '24px';
        fallback.style.borderRadius = '8px';
        fallback.textContent = letter;
        iconContainer.insertBefore(fallback, iconImg);
      }
    };
  }

  document.getElementById('modal-tech-name').textContent = techName;
  document.getElementById('modal-category').textContent = 'Loading...';
  document.getElementById('modal-tech-usage').textContent = '-';

  document.getElementById('modal-tech-share').textContent = '-';

  const dList = document.getElementById('modal-domains-list');
  dList.innerHTML = '<li class="loading-text">Loading domains...</li>';
  document.getElementById('modal-domain-count').textContent = '...';

  const drillLink = document.getElementById('tech-drill-link');
  drillLink.href = `/explorer?q=${encodeURIComponent(techName)}`;

  techModalDomains = [];

  try {
    // 1. Fetch from correct endpoint /sites (not /domains which was 404)
    const res = await fetch(`/api/tech/${encodeURIComponent(techName)}/sites?limit=500&t=${Date.now()}`);
    const data = await res.json();

    // 2. Fetch basic meta for categories (since /sites response might not include full category list)
    // We try to use what we have or fallback
    let techCats = [];
    if (data.sites && data.sites.length > 0 && data.sites[0].summary && data.sites[0].summary.category) {
      // Try to infer from first site? Unreliable.
      // Better to rely on fallback or separate call if needed.
      // For now, let's stick to fallback or what we display in top list.
    }
    // Ideally we should call /api/techs/NAME first to get meta, but for speed let's just use what we have + fallback
    const catStr = getFallbackCategory(techName) || '-';
    document.getElementById('modal-category').textContent = catStr;


    // 3. Usage Count
    let uCount = data.total || (data.sites ? data.sites.length : 0);
    document.getElementById('modal-tech-usage').textContent = uCount.toLocaleString();

    // 4. Share of Top Stack
    const totalDomEl = document.getElementById('total-domains');
    let shareText = 'N/A';
    if (totalDomEl) {
      const totalDomains = parseInt(totalDomEl.textContent.replace(/,/g, ''), 10) || 0;
      if (totalDomains > 0 && uCount > 0) {
        const pct = ((uCount / totalDomains) * 100).toFixed(1);
        shareText = `${pct}%`;
      }
    }
    document.getElementById('modal-tech-share').textContent = shareText;

    if (data.sites && data.sites.length > 0) {
      // Map sites objects to domain strings
      techModalDomains = data.sites.map(s => s.domain);
      filterTechModalDomains('');
    } else {
      dList.innerHTML = '<li class="loading-text">No domains found</li>';
      document.getElementById('modal-domain-count').textContent = '0 domains';
    }
  } catch (e) {
    console.error(e);
    dList.innerHTML = '<li class="loading-text" style="color:#f87171;">Error loading details</li>';
  }
}

function copyTechName() {
  const name = document.getElementById('modal-tech-name').textContent;
  if (name) {
    navigator.clipboard.writeText(name).then(() => {
      const btn = document.getElementById('copy-tech-btn');
      const original = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = original, 1500);
    });
  }
}

function filterTechModalDomains(query) {
  const dList = document.getElementById('modal-domains-list');
  const dCount = document.getElementById('modal-domain-count');
  const domainSearch = document.getElementById('modal-domain-search');

  if (!techModalDomains.length) return;

  const q = query.toLowerCase().trim();
  const filtered = q ? techModalDomains.filter(d => d.toLowerCase().includes(q)) : techModalDomains;

  // Limit rendering to 50 items to prevent DOM freezing
  const limit = 50;
  const renderSet = filtered.slice(0, limit);

  try {
    if (renderSet.length > 0) {
      dList.innerHTML = renderSet.map(d =>
        `<li>
           <a href="https://${d}" target="_blank" rel="noopener noreferrer">${d}</a>
           <a href="/explorer?q=${encodeURIComponent(d)}" target="_blank" style="opacity:0.5;font-size:0.7em;text-decoration:none;">🔍</a>
         </li>`
      ).join('');

      if (filtered.length > limit) {
        const more = document.createElement('li');
        more.style.textAlign = 'center';
        more.style.opacity = '0.7';
        more.style.fontStyle = 'italic';
        more.textContent = `...and ${filtered.length - limit} more`;
        dList.appendChild(more);
      }
    } else {
      dList.innerHTML = '<li class="loading-text">No matching domains</li>';
    }

    if (dCount) dCount.textContent = `${filtered.length} domains`;
  } finally {
    if (domainSearch) {
      domainSearch.disabled = !techModalDomains.length;
    }
  }
}

function closeTechModal() {
  document.getElementById('techModal').classList.add('hidden');
  const domainSearch = document.getElementById('modal-domain-search');
  if (domainSearch) {
    domainSearch.value = '';
    domainSearch.disabled = false;
  }
  techModalDomains = [];
}

async function openCategoryModal(categoryName) {
  document.getElementById('categoryModal').classList.remove('hidden');
  document.getElementById('modal-cat-name').textContent = categoryName;

  // RESET side modal completely - clear all data
  const sideModal = document.getElementById('sideTechModal');
  sideModal.style.display = 'none';
  document.getElementById('side-modal-tech-name').textContent = '';
  document.getElementById('side-modal-category').textContent = '';
  document.getElementById('side-modal-domains-list').innerHTML = '';

  // Destroy previous chart if exists to prevent stale data
  if (categoryChartInstance) {
    categoryChartInstance.destroy();
    categoryChartInstance = null;
  }

  // Clear table to prevent showing old data
  const tbody = document.getElementById('modal-cat-tech-body');
  tbody.innerHTML = '<tr><td colspan="2" class="loading-text" style="text-align:center;">Loading...</td></tr>';

  // Fetch technologies in this category with cache busting
  try {
    const res = await fetch(`/api/category/${encodeURIComponent(categoryName)}/technologies?t=${Date.now()}`);
    const data = await res.json();

    if (data.technologies && data.technologies.length > 0) {
      const techs = data.technologies; // Show all technologies, not just top 10
      const labels = techs.map(t => t.tech);
      const counts = techs.map(t => t.count);

      // Create horizontal bar chart
      const ctx = document.getElementById('categoryTechChart');
      categoryChartInstance = makeBarChart('categoryTechChart', labels, counts, '#60a5fa');

      // Populate table with fresh data
      tbody.innerHTML = '';
      techs.forEach(t => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td style="font-weight:600;">${t.tech}</td><td style="text-align:right;font-weight:600;">${t.count}</td>`;
        tr.addEventListener('click', () => openSideTechModal(t));
        tr.style.cursor = 'pointer';
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = '<tr><td colspan="2" class="loading-text" style="text-align:center;">No technologies found</td></tr>';
    }
  } catch (e) {
    console.error('Failed to load category data', e);
    tbody.innerHTML = '<tr><td colspan="2" class="loading-text" style="text-align:center;">Error loading data</td></tr>';
  }
}

function closeCategoryModal() {
  document.getElementById('categoryModal').classList.add('hidden');
  if (categoryChartInstance) {
    categoryChartInstance.destroy();
    categoryChartInstance = null;
  }
}

async function openSideTechModal(tech) {
  const sideModal = document.getElementById('sideTechModal');
  sideModal.style.display = 'block';

  document.getElementById('side-modal-tech-name').textContent = tech.tech;
  const categories = Array.isArray(tech.categories) ? tech.categories : normalizeCategories(tech.categories || tech.category);
  const category = categories.length ? categories.join(', ') : '-';
  document.getElementById('side-modal-category').textContent = 'Category: ' + category;

  // Clear previous data and show loading
  const domainsList = document.getElementById('side-modal-domains-list');
  domainsList.innerHTML = '<li class="loading-text" style="font-size:0.85rem;">Loading domains...</li>';

  try {
    // Fresh fetch with cache busting using correct endpoint /sites
    const res = await fetch(`/api/tech/${encodeURIComponent(tech.tech)}/sites?limit=50&t=${Date.now()}`);
    const data = await res.json();

    if (data.sites && data.sites.length > 0) {
      const doms = data.sites.map(s => s.domain);
      domainsList.innerHTML = doms.map(d =>
        `<li style="padding:0.4rem;background:rgba(255,255,255,0.05);margin:0.25rem 0;border-radius:0.3rem;font-size:0.85rem;"><a href="https://${d}" target="_blank" style="color:#60a5fa;text-decoration:none;">${d}</a></li>`
      ).join('');
    } else {
      domainsList.innerHTML = '<li class="loading-text" style="font-size:0.85rem;">No domains found</li>';
    }
  } catch (e) {
    domainsList.innerHTML = '<li class="loading-text" style="font-size:0.85rem;">Failed to load domains</li>';
  }
}

function closeSideTechModal() {
  document.getElementById('sideTechModal').style.display = 'none';
}

const CATEGORY_SEGMENT_PALETTE = ['#22c55e', '#60a5fa', '#fbbf24', '#f472b6', '#a78bfa', '#fb923c', '#14b8a6', '#f43f5e', '#8b5cf6', '#06b6d4'];
const CATEGORY_CARD_LIMIT = 30;

function buildCategorySegments(techList, uniqueDomainCount, displayLabel) {
  const fallbackLabel = displayLabel || 'Unknown';
  // 1. Normalize and Sort (Safety: Ensure sorted descending by count)
  const normalized = Array.isArray(techList)
    ? techList
      .map(item => {
        const rawName = item && (item.name || item.tech || item.label);
        const name = rawName ? String(rawName).trim() : fallbackLabel;
        const count = Number(item && item.count);
        return { name, count: Number.isFinite(count) && count > 0 ? count : 0 };
      })
      .filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count)
    : [];

  // 2. Calculate true total of all technology occurrences (Usage Share)
  // We cannot use uniqueDomainCount for the pie/doughnut total because
  // one domain can have multiple techs in the same category (e.g. React + Vue),
  // making the sum of tech counts > uniqueDomainCount.
  const grandTotalOccurrences = normalized.reduce((sum, item) => sum + item.count, 0);

  const maxSegments = 6;
  const limited = normalized.slice(0, maxSegments);
  let usedSegmentTotal = limited.reduce((sum, item) => sum + item.count, 0);

  // If no data, return synthetic empty state using uniqueDomainCount if available, else 0
  if (!limited.length) {
    const fallbackCount = Number(uniqueDomainCount) || 0;
    if (fallbackCount > 0) {
      return {
        segments: [{ name: fallbackLabel, count: fallbackCount, isSynthetic: true }],
        total: fallbackCount
      };
    }
    return { segments: [], total: 0 };
  }

  const segments = limited.slice();

  // 3. Add "Other" segment if there are leftovers in the list
  // The budget is the grandTotalOccurrences of the technologies.
  if (grandTotalOccurrences > usedSegmentTotal) {
    const remainder = grandTotalOccurrences - usedSegmentTotal;
    segments.push({ name: 'Other', count: remainder, isRemainder: true });
    usedSegmentTotal += remainder;
  }

  // Double check we have something to render
  if (!segments.length) {
    segments.push({ name: fallbackLabel, count: 1, isSynthetic: true });
    usedSegmentTotal = 1;
  }

  return { segments, total: usedSegmentTotal };
}

function renderCategoryTopTechList(container, segments) {
  if (!container) return;
  const meaningfulSegments = Array.isArray(segments)
    ? segments.filter(item => item && !item.isRemainder && !item.isSynthetic && (Number(item.count) || 0) > 0)
    : [];

  if (!meaningfulSegments.length) {
    container.innerHTML = '<div class="loading-text" style="margin-top:0.75rem;font-size:0.75rem;">No top technologies mapped yet</div>';
    return;
  }

  const listMarkup = `<ul style="list-style:none;padding:0;margin:0.75rem 0 0;width:100%;display:flex;flex-direction:column;gap:0.4rem;">${meaningfulSegments.map(seg => {
    const name = escapeHtml(seg.name || 'Unknown');
    const count = Number(seg.count) || 0;
    const countLabel = count ? count.toLocaleString('en-US') : '-';
    return `<li style="display:flex;justify-content:space-between;align-items:center;font-size:0.78rem;color:var(--ts-text, rgba(255,255,255,0.85));"><span style="font-weight:500;">${name}</span><span style="color:var(--ts-text-dim, rgba(255,255,255,0.65));font-size:0.72rem;">${countLabel}</span></li>`;
  }).join('')}</ul>`;
  container.innerHTML = listMarkup;
}

function updateCategoryChart(chart, segmentBundle, palette, fallbackLabel) {
  if (!chart || !segmentBundle) return;
  const segments = Array.isArray(segmentBundle.segments) ? segmentBundle.segments : [];
  if (!segments.length) return;
  const total = Number(segmentBundle.total) || segments.reduce((sum, seg) => sum + (Number(seg.count) || 0), 0) || 1;
  const colors = segments.map((_, idx) => palette[idx % palette.length]);

  chart.data.datasets[0].data = segments.map(seg => {
    const value = Number(seg.count);
    return Number.isFinite(value) && value > 0 ? value : 1;
  });
  chart.data.datasets[0].backgroundColor = colors;
  chart.data.labels = segments.map(seg => {
    const labelBase = seg && seg.name ? seg.name : fallbackLabel;
    const value = Number(seg.count) || 0;
    const pct = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
    return value ? `${labelBase} (${value.toLocaleString('en-US')} · ${pct}%)` : labelBase;
  });
  chart.update();
}

async function hydrateCategoryCard(details) {
  const { categoryName, displayName, chart, listContainer, palette, totalCount, fallbackData, cardElement } = details;
  if (!categoryName || !chart) return;

  const hasMeaningfulFallback = fallbackData
    && Array.isArray(fallbackData.segments)
    && fallbackData.segments.some(item => item && !item.isRemainder && !item.isSynthetic && (Number(item.count) || 0) > 0);

  if (listContainer && !hasMeaningfulFallback) {
    listContainer.innerHTML = '<div class="loading-text" style="margin-top:0.75rem;font-size:0.75rem;">Loading breakdown...</div>';
  }

  try {
    const res = await fetch(`/api/category/${encodeURIComponent(categoryName)}/technologies?t=${Date.now()}`, { cache: 'no-store' });
    if (!res || !res.ok) {
      throw new Error(`category fetch failed status=${res ? res.status : 'n/a'}`);
    }
    const payload = await res.json();
    const techs = payload && Array.isArray(payload.technologies) ? payload.technologies : [];

    // For uncategorized category, recalculate total from filtered techs
    let effectiveTotalCount = totalCount;
    if (categoryName.toLowerCase() === 'uncategorized' && techs.length > 0) {
      effectiveTotalCount = techs.reduce((sum, t) => sum + (Number(t.count) || 0), 0);
      // Update the count display in the card
      if (cardElement) {
        const countEl = cardElement.querySelector('.category-usage-count');
        if (countEl) {
          countEl.textContent = effectiveTotalCount ? `${effectiveTotalCount.toLocaleString('en-US')} usages` : 'No usage data';
        }
      }
    }

    const segmentsData = buildCategorySegments(techs, effectiveTotalCount, displayName);
    if (!segmentsData.segments.length) {
      throw new Error('empty category segments');
    }
    updateCategoryChart(chart, segmentsData, palette, displayName);
    renderCategoryTopTechList(listContainer, segmentsData.segments);
  } catch (err) {
    console.warn('category breakdown fallback', categoryName, err);
    if (fallbackData) {
      updateCategoryChart(chart, fallbackData, palette, displayName);
      renderCategoryTopTechList(listContainer, fallbackData.segments);
    } else if (listContainer) {
      listContainer.innerHTML = '<div class="loading-text" style="margin-top:0.75rem;font-size:0.75rem;">No technologies found</div>';
    }
  }
}

async function renderCategoryClassification(categories) {
  const container = document.getElementById('category-charts-container');

  Object.keys(categoryPieCharts).forEach(key => {
    if (categoryPieCharts[key]) {
      categoryPieCharts[key].destroy();
    }
  });
  categoryPieCharts = {};
  container.innerHTML = '';

  const usableCategories = Array.isArray(categories)
    ? categories.filter(cat => cat && (cat.category || cat.rawCategory))
    : [];
  const topCategories = CATEGORY_CARD_LIMIT > 0
    ? usableCategories.slice(0, CATEGORY_CARD_LIMIT)
    : usableCategories;
  if (!topCategories.length) {
    container.innerHTML = '<div class="loading-text" style="padding:1rem;">No category data available</div>';
    return;
  }

  // Process sequentially to avoid 429 storms
  for (const [idx, cat] of topCategories.entries()) {
    const displayName = cat && (cat.category || cat.rawCategory) ? escapeHtml(cat.category || cat.rawCategory) : 'Unknown';
    const rawName = cat && (cat.rawCategory || cat.category) ? String(cat.rawCategory || cat.category) : 'Unknown';
    const totalCount = Number(cat && cat.count) || 0;
    const usageText = totalCount ? `${totalCount.toLocaleString('en-US')} usages` : 'Usage data unavailable';
    const techEntries = Array.isArray(cat && cat.techs) ? cat.techs : [];
    const fallbackData = buildCategorySegments(techEntries, totalCount, displayName);

    const chartDiv = document.createElement('div');
    chartDiv.style.cssText = 'min-width:230px;max-width:230px;display:flex;flex-direction:column;align-items:center;cursor:pointer;background:rgba(255,255,255,0.08);padding:1rem;border-radius:0.8rem;transition:all 0.3s ease;scroll-snap-align:start;';
    chartDiv.classList.add('category-card');

    const cardMarkup = `
    <h4 style="font-size:0.95rem;font-weight:600;margin-bottom:0.8rem;text-align:center;min-height:2.5rem;display:flex;align-items:center;justify-content:center;">${displayName}</h4>
    <div style="position:relative;height:160px;width:160px;">
      <canvas id="cat-pie-${idx}"></canvas>
    </div>
    <div class="category-usage-count">${usageText}</div>
    <div data-role="category-tech-list" style="width:100%;"></div>
  `;

    chartDiv.innerHTML = cardMarkup;
    chartDiv.addEventListener('click', () => openCategoryModal(rawName));
    container.appendChild(chartDiv);

    const listContainer = chartDiv.querySelector('[data-role="category-tech-list"]');
    renderCategoryTopTechList(listContainer, fallbackData.segments);

    // Render chart
    const canvasId = `cat-pie-${idx}`;
    const ctx = document.getElementById(canvasId);
    if (ctx && ensureChartLib()) {
      const chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: [],
            borderWidth: 3,
            borderColor: 'rgba(255,255,255,0.1)'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: 'rgba(0,0,0,0.9)',
              titleColor: '#fff',
              bodyColor: '#fff',
              borderWidth: 1,
              padding: 10,
              borderColor: function (context) {
                const colors = context && context.chart && context.chart.data && context.chart.data.datasets && context.chart.data.datasets[0] && context.chart.data.datasets[0].backgroundColor;
                const index = context && typeof context.dataIndex === 'number' ? context.dataIndex : 0;
                return Array.isArray(colors) ? (colors[index] || '#60a5fa') : '#60a5fa';
              },
              callbacks: {
                label: function (context) {
                  const datasetValues = context && context.dataset && Array.isArray(context.dataset.data)
                    ? context.dataset.data
                    : [];
                  const total = datasetValues.reduce((a, b) => a + b, 0) || 1;
                  const value = Number(context && context.parsed) || 0;
                  const percentage = ((value / total) * 100).toFixed(1);
                  const hoverLabel = context && typeof context.label === 'string' ? context.label : 'Value';
                  return `${hoverLabel}: ${value.toLocaleString('en-US')} (${percentage}%)`;
                }
              }
            }
          }
        }
      });

      categoryPieCharts[canvasId] = chart;
      updateCategoryChart(chart, fallbackData, CATEGORY_SEGMENT_PALETTE, displayName);

      // Fire off the details fetch (no await here, let it run)
      hydrateCategoryCard({
        categoryName: rawName,
        displayName,
        chart,
        listContainer,
        palette: CATEGORY_SEGMENT_PALETTE,
        totalCount,
        fallbackData,
        cardElement: chartDiv
      });
    }

    // Small delay before rendering next card's expensive ops & network
    await new Promise(r => setTimeout(r, 600));
  }
}

function scrollCarousel(direction) {
  const container = document.querySelector('.carousel-container');
  const scrollAmount = 250; // width of one card + gap
  container.scrollLeft += direction * scrollAmount;
}

const modalDomainSearch = document.getElementById('modal-domain-search');
if (modalDomainSearch) {
  modalDomainSearch.addEventListener('input', () => filterTechModalDomains(modalDomainSearch.value || ''));
}
const copyTechBtnRef = document.getElementById('copy-tech-btn');
if (copyTechBtnRef) {
  copyTechBtnRef.addEventListener('click', copyTechName);
}

fetchStats();

// Auto-refresh controlled via config
const autoRefreshEnabled = window.TECHSCAN_CONFIG.STATS_AUTO_REFRESH === "true";
const autoRefreshInterval = parseInt(window.TECHSCAN_CONFIG.STATS_AUTO_REFRESH_INTERVAL_MS, 10);
let statsRefreshTimer = null;

if (autoRefreshEnabled) {
  statsRefreshTimer = setInterval(fetchStats, autoRefreshInterval);
  console.log('[stats] Auto-refresh enabled, interval:', autoRefreshInterval, 'ms');
} else {
  console.log('[stats] Auto-refresh disabled. Use Ctrl+F5 or refresh button to update.');
}

// Cleanup saat page unload (optional, good practice)
window.addEventListener('beforeunload', () => {
  if (uptimeInterval) clearInterval(uptimeInterval);
  if (statsRefreshTimer) clearInterval(statsRefreshTimer);
});

// Enable horizontal scroll with mouse wheel on carousel
document.addEventListener('DOMContentLoaded', function () {
  const carousel = document.getElementById('carousel-container');
  if (carousel) {
    carousel.addEventListener('wheel', function (e) {
      if (e.deltaY !== 0) {
        e.preventDefault();
        carousel.scrollLeft += e.deltaY;
      }
    }, { passive: false });
  }
});
