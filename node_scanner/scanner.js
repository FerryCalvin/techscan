#!/usr/bin/env node
// Lightweight wrapper to scan a single domain and print normalized JSON.
// Adds Windows Chrome/Edge executable auto-detection so you can set PUPPETEER_SKIP_DOWNLOAD=1 during install.
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import Wappalyzer from 'wappalyzer'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const argv = process.argv.slice(2)
if (argv.length < 1) {
  console.error('Usage: node scanner.js <url>')
  process.exit(1)
}
let url = argv[0]
if (!/^https?:\/\//i.test(url)) url = 'https://' + url

// Attempt to locate a system Chrome/Edge executable on Windows if Puppeteer executable path not provided.
function ensureBrowserExecutable() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return // user already set it
  const isWin = process.platform === 'win32'
  if (!isWin) return // only needed on Windows in this project context
  const env = process.env
  const candidates = []
  const pf = env['PROGRAMFILES']
  const pfx86 = env['PROGRAMFILES(X86)']
  const localApp = env['LOCALAPPDATA']
  // Common Chrome locations
  if (pf) candidates.push(path.join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'))
  if (pfx86) candidates.push(path.join(pfx86, 'Google', 'Chrome', 'Application', 'chrome.exe'))
  if (localApp) candidates.push(path.join(localApp, 'Google', 'Chrome', 'Application', 'chrome.exe'))
  // Edge (Chromium) locations
  if (pf) candidates.push(path.join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe'))
  if (pfx86) candidates.push(path.join(pfx86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'))
  const found = candidates.find(p => {
    try { return fs.existsSync(p) } catch { return false }
  })
  if (found) {
    process.env.PUPPETEER_EXECUTABLE_PATH = found
    if (process.env.TECHSCAN_DEBUG) {
      console.error(`[techscan] Using system Chromium executable: ${found}`)
    }
  } else {
    if (process.env.TECHSCAN_DEBUG) {
      console.error('[techscan] No system Chrome/Edge executable found; Puppeteer will use its managed binary (if installed).')
    }
  }
}

ensureBrowserExecutable()

const CUSTOM_SIGNATURES = loadCustomSignatures()

const COOKIE_HINT_PATTERNS = [
  { name: 'Laravel', regex: /laravel_session/i, label: 'laravel_session' },
  { name: 'Laravel', regex: /xsrf-token/i, label: 'xsrf_token' },
  { name: 'CodeIgniter', regex: /ci_session/i, label: 'ci_session' },
  { name: 'WordPress', regex: /wordpress_(?:test_|logged_in|sec|settings)/i, label: 'wordpress_cookie' },
  { name: 'PHP', regex: /phpsessid/i, label: 'phpsessid' }
]

const CSP_HINT_PATTERNS = [
  { name: 'Next.js', regex: /next/i, label: 'csp-next' },
  { name: 'Nuxt.js', regex: /nuxt/i, label: 'csp-nuxt' },
  { name: 'Laravel', regex: /laravel/i, label: 'csp-laravel' },
  { name: 'Symfony', regex: /_profiler|symfony/i, label: 'csp-symfony' },
  { name: 'Shopify', regex: /cdn\.shopify\.com/i, label: 'csp-shopify' }
]

function dedupeObjects(items = []) {
  const seen = new Set()
  return items.filter(item => {
    const key = JSON.stringify(item)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function dedupeStrings(items = []) {
  const seen = new Set()
  return items.filter(item => {
    const key = String(item)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function loadCustomSignatures() {
  const customPath = path.join(__dirname, 'custom_signatures.json')
  try {
    if (!fs.existsSync(customPath)) return null
    const raw = fs.readFileSync(customPath, 'utf8')
    const parsed = JSON.parse(raw)
    if (parsed && Array.isArray(parsed.technologies)) return parsed
  } catch (err) {
    if (process.env.TECHSCAN_DEBUG) {
      console.error('[techscan] custom signatures load failed:', err.message || String(err))
    }
  }
  return null
}

function applyCustomSignatures({ extras, hintMeta, techs, signatures }) {
  if (!signatures || !Array.isArray(signatures.technologies)) return []
  const existing = new Set((techs || []).map(t => t.name))
  const additions = []
  const ctx = {
    scripts: (extras && extras.scripts) ? extras.scripts : [],
    links: (extras && extras.links) ? extras.links : [],
    metaKeys: extras && extras.meta ? Object.keys(extras.meta) : [],
    metaValues: extras && extras.meta ? Object.values(extras.meta) : [],
    bodyClasses: (extras && extras.body_classes) ? extras.body_classes : [],
    globals: extras && extras.globals ? Object.entries(extras.globals).map(([k, v]) => `${k}:${v}`) : [],
    serviceWorkers: hintMeta && hintMeta.service_worker_sources ? hintMeta.service_worker_sources : [],
    manifestUrls: hintMeta && hintMeta.manifest_hits ? hintMeta.manifest_hits : [],
    cookies: hintMeta && Array.isArray(hintMeta.cookie_hits) ? hintMeta.cookie_hits.map(c => c.cookie || c.label || '') : [],
    csp: hintMeta && Array.isArray(hintMeta.csp_hits) ? hintMeta.csp_hits.map(c => c.label || '') : []
  }
  const validFields = new Set(Object.keys(ctx))
  signatures.technologies.forEach(def => {
    if (!def || !def.name || existing.has(def.name)) return
    const rules = Array.isArray(def.rules) ? def.rules : []
    if (!rules.length) return
    const minHits = Number.isFinite(def.minHits) ? def.minHits : 1
    let hitCount = 0
    let inferredVersion = null
    const evidence = []
    rules.forEach(rule => {
      if (!rule || !rule.field || !validFields.has(rule.field) || !rule.pattern) return
      const values = ctx[rule.field] || []
      let lastMatch = null
      let matched = false
      for (const val of values) {
        try {
          const re = new RegExp(rule.pattern, rule.flags || 'i')
          const m = String(val).match(re)
          if (m) {
            matched = true
            lastMatch = String(val)
            if (!inferredVersion && rule.versionGroup && m[rule.versionGroup]) {
              inferredVersion = m[rule.versionGroup]
            }
            break
          }
        } catch (err) {
          if (process.env.TECHSCAN_DEBUG) {
            console.error('[techscan] invalid custom rule regex:', rule.pattern, err.message || String(err))
          }
        }
      }
      if (matched) {
        hitCount += 1
        evidence.push({
          kind: 'custom',
          source: rule.field,
          pattern: rule.pattern,
          match: lastMatch
        })
      }
    })
    if (hitCount >= minHits) {
      additions.push({
        name: def.name,
        version: def.version || inferredVersion || null,
        categories: Array.isArray(def.categories) && def.categories.length ? def.categories : ['Custom'],
        confidence: def.confidence || 40,
        evidence
      })
      existing.add(def.name)
    }
  })
  return additions
}

async function getPrimaryPage(site) {
  if (!site || !site.driver || !site.driver.browser || typeof site.driver.browser.pages !== 'function') {
    return null
  }
  const isUsable = p => {
    try {
      const u = p.url()
      return u && u !== 'about:blank' && !u.startsWith('chrome-error://')
    } catch {
      return false
    }
  }
  // Prefer a cached usable page
  if (site._techscanPrimaryPage && isUsable(site._techscanPrimaryPage)) {
    return site._techscanPrimaryPage
  }
  // Puppeteer driver often exposes a page field; prefer it if available
  if (site.driver.page && isUsable(site.driver.page)) {
    site._techscanPrimaryPage = site.driver.page
    return site.driver.page
  }
  try {
    // Gather pages from all contexts (incognito contexts are not returned by browser.pages())
    const contexts = typeof site.driver.browser.browserContexts === 'function'
      ? site.driver.browser.browserContexts()
      : []
    const allPages = []
    contexts.forEach(ctx => {
      try {
        if (ctx && typeof ctx.pages === 'function') {
          allPages.push(...(ctx.pages() || []))
        }
      } catch { }
    })
    // Fallback to default context pages if none collected
    if (!allPages.length) {
      try {
        const defaultPages = await site.driver.browser.pages()
        if (Array.isArray(defaultPages)) allPages.push(...defaultPages)
      } catch { }
    }
    let page = null
    if (allPages.length) {
      page = allPages.find(isUsable) || allPages[allPages.length - 1] || allPages[0]
    }
    if (page && isUsable(page)) {
      site._techscanPrimaryPage = page
      return page
    }
  } catch {
    // fall through to fresh page creation
  }
  // As a last resort, open a fresh page in the same browser and navigate to the target URL
  try {
    const browser = site.driver.browser
    if (browser && typeof browser.newPage === 'function') {
      const freshPage = await browser.newPage()
      if (freshPage) {
        try { await freshPage.setUserAgent('Mozilla/5.0 (TechScan)') } catch { }
        const fallbackUrl = url
        const timeout = parseInt(process.env.TECHSCAN_NAV_TIMEOUT || '15000', 10)
        try {
          await freshPage.goto(fallbackUrl, { waitUntil: 'domcontentloaded', timeout: timeout || 15000 })
        } catch { }
        if (isUsable(freshPage)) {
          site._techscanPrimaryPage = freshPage
          return freshPage
        }
      }
    }
  } catch { }
  return null
}

async function collectHintMeta(site) {
  if (process.env.TECHSCAN_RUNTIME_HINTS === '0') {
    return null
  }
  const page = await getPrimaryPage(site)
  if (!page) {
    return null
  }
  const meta = {}
  let domData = null
  try {
    domData = await page.evaluate(async () => {
      const runtimeHits = []
      const formHits = []
      const manifestHits = []
      const fontHits = []
      const serviceWorkers = []
      const addRuntime = (cond, payload) => { if (cond) runtimeHits.push(payload) }
      try { addRuntime(Boolean(window.__NEXT_DATA__), { name: 'Next.js', label: 'next-data-inline' }) } catch { }
      try { addRuntime(Boolean(window.__NUXT__), { name: 'Nuxt.js', label: 'nuxt-inline' }) } catch { }
      try { addRuntime(Boolean(window.__remixManifest), { name: 'Remix', label: 'remix-manifest' }) } catch { }
      try { addRuntime(Boolean(window.Livewire), { name: 'Livewire', label: 'livewire-runtime' }) } catch { }
      try { addRuntime(Boolean(window.Inertia), { name: 'Inertia.js', label: 'inertia-runtime' }) } catch { }
      try { addRuntime(Boolean(window.Alpine), { name: 'Alpine.js', label: 'alpine-runtime' }) } catch { }
      try { addRuntime(Boolean(window.Shopify), { name: 'Shopify', label: 'shopify-runtime' }) } catch { }
      try { addRuntime(Boolean(window.drupalSettings), { name: 'Drupal', label: 'drupal-settings' }) } catch { }
      let importMap = false
      try { importMap = Boolean(document.querySelector('script[type="importmap"]')) } catch { }
      try {
        document.querySelectorAll('link[rel="manifest"]').forEach(node => {
          const href = node.getAttribute('href') || ''
          if (!href) return
          try {
            manifestHits.push(new URL(href, window.location.href).href)
          } catch {
            manifestHits.push(href)
          }
        })
      } catch { }
      try {
        document.querySelectorAll('link[href],script[src]').forEach(node => {
          const ref = node.getAttribute('href') || node.getAttribute('src') || ''
          const lower = (ref || '').toLowerCase()
          if (!lower) return
          if (lower.includes('bootstrap-icons')) {
            fontHits.push({ name: 'Bootstrap Icons', label: 'asset' })
          } else if (lower.includes('materialicons')) {
            fontHits.push({ name: 'Material Icons', label: 'asset' })
          } else if (lower.includes('primeicons')) {
            fontHits.push({ name: 'PrimeIcons', label: 'asset' })
          }
        })
      } catch { }
      try {
        document.querySelectorAll('input[name]').forEach(input => {
          const name = (input.getAttribute('name') || '').toLowerCase()
          if (!name) return
          if (name === '_token') {
            formHits.push({ name: 'Laravel', label: 'csrf_token' })
          } else if (name === 'ci_csrf_token') {
            formHits.push({ name: 'CodeIgniter', label: 'ci_csrf_token' })
          } else if (name === 'csrfmiddlewaretoken') {
            formHits.push({ name: 'Django', label: 'django_csrf' })
          }
        })
      } catch { }
      try {
        if (navigator.serviceWorker) {
          if (navigator.serviceWorker.controller && navigator.serviceWorker.controller.scriptURL) {
            serviceWorkers.push(navigator.serviceWorker.controller.scriptURL)
          }
          if (navigator.serviceWorker.getRegistrations) {
            try {
              const regs = await navigator.serviceWorker.getRegistrations()
              regs.forEach(reg => {
                ;['installing', 'waiting', 'active'].forEach(state => {
                  const worker = reg[state]
                  if (worker && worker.scriptURL) {
                    serviceWorkers.push(worker.scriptURL)
                  }
                })
              })
            } catch { }
          }
        }
      } catch { }
      let cspText = ''
      try {
        const metaTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]')
        if (metaTag) {
          cspText = metaTag.getAttribute('content') || ''
        }
      } catch { }
      let cookieString = ''
      try { cookieString = document.cookie || '' } catch { }
      return {
        runtimeHits,
        formHits,
        manifestHits,
        fontHits,
        serviceWorkers,
        importMap,
        cspText,
        cookieString
      }
    })
  } catch (err) {
    if (process.env.TECHSCAN_DEBUG) {
      console.error('[techscan] runtime hint collection failed:', err.message || String(err))
    }
  }
  if (domData) {
    if (domData.runtimeHits && domData.runtimeHits.length) {
      meta.runtime_hits = dedupeObjects(domData.runtimeHits).slice(0, 12)
    }
    if (domData.formHits && domData.formHits.length) {
      meta.form_hits = dedupeObjects(domData.formHits).slice(0, 8)
    }
    if (domData.manifestHits && domData.manifestHits.length) {
      meta.manifest_hits = dedupeStrings(domData.manifestHits).slice(0, 5)
    }
    if (domData.serviceWorkers && domData.serviceWorkers.length) {
      meta.service_worker_sources = dedupeStrings(domData.serviceWorkers).slice(0, 5)
    }
    if (domData.fontHits && domData.fontHits.length) {
      meta.font_hits = dedupeObjects(domData.fontHits).slice(0, 8)
    }
    if (domData.importMap) {
      meta.import_map = true
    }
    if (domData.cspText) {
      const matches = []
      const lowered = domData.cspText.toLowerCase()
      CSP_HINT_PATTERNS.forEach(pattern => {
        if (pattern.regex.test(lowered)) {
          matches.push({ name: pattern.name, label: pattern.label })
        }
      })
      if (matches.length) {
        meta.csp_hits = dedupeObjects(matches)
      }
    }
  }
  try {
    const cookies = await page.cookies()
    if (cookies && cookies.length) {
      const hits = []
      cookies.forEach(cookie => {
        COOKIE_HINT_PATTERNS.forEach(pattern => {
          if (pattern.regex.test(cookie.name)) {
            hits.push({ name: pattern.name, label: pattern.label, cookie: cookie.name })
          }
        })
      })
      if (hits.length) {
        meta.cookie_hits = dedupeObjects(hits).slice(0, 10)
      }
    }
  } catch { }
  if ((!meta.cookie_hits || !meta.cookie_hits.length) && domData && domData.cookieString) {
    const rawNames = domData.cookieString.split(';').map(chunk => chunk.split('=')[0].trim()).filter(Boolean)
    if (rawNames.length) {
      const fallbackHits = []
      rawNames.forEach(name => {
        COOKIE_HINT_PATTERNS.forEach(pattern => {
          if (pattern.regex.test(name)) {
            fallbackHits.push({ name: pattern.name, label: pattern.label, cookie: name })
          }
        })
      })
      if (fallbackHits.length) {
        meta.cookie_hits = dedupeObjects(fallbackHits).slice(0, 10)
      }
    }
  }
  return Object.keys(meta).length ? meta : null
}

async function collectExtras(site) {
  const page = await getPrimaryPage(site)
  if (!page) {
    return null
  }
  try {
    const domInfo = await page.evaluate(() => {
      try {
        const metas = {}
        document.querySelectorAll('meta[name],meta[property]').forEach(node => {
          const key = (node.getAttribute('name') || node.getAttribute('property') || '').toLowerCase()
          if (key && !(key in metas)) {
            metas[key] = (node.getAttribute('content') || '').trim()
          }
        })
        const scripts = Array.from(document.scripts || [])
          .map(s => (s && s.src) ? s.src : '')
          .filter(u => !!u)
        const links = Array.from(document.querySelectorAll('link[href]') || [])
          .map(l => (l && l.href) ? l.href : '')
          .filter(u => !!u)
        const globals = {}
        try {
          if (window && window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
            globals.jquery = String(window.jQuery.fn.jquery)
          }
        } catch { }
        try {
          if (window && window.Vue && window.Vue.version) {
            globals.vue = String(window.Vue.version)
          }
        } catch { }
        try {
          if (window && window.angular && window.angular.version && window.angular.version.full) {
            globals.angularjs = String(window.angular.version.full)
          }
        } catch { }
        let bodyClasses = []
        try {
          if (document.body && document.body.className) {
            bodyClasses = document.body.className.split(/\s+/).filter(Boolean)
          }
        } catch { }
        return {
          metas,
          scripts,
          links,
          globals,
          url: window.location.href,
          bodyClasses
        }
      } catch (e) {
        return null
      }
    })
    if (domInfo) {
      return {
        meta: domInfo.metas || {},
        scripts: domInfo.scripts || [],
        links: domInfo.links || [],
        globals: domInfo.globals || {},
        url: domInfo.url || '',
        body_classes: domInfo.bodyClasses || []
      }
    }
  } catch (err) {
    if (process.env.TECHSCAN_DEBUG) {
      console.error('[techscan] extras collection failed:', err.message || String(err))
    }
  }
  return null
}

function inferSnippetFromUrl(url) {
  if (!url) return null
  const clean = url.split('#')[0]
  if (/\.css(\?|$)/i.test(clean)) {
    return `<link rel="stylesheet" href="${clean}">`
  }
  if (/\.js(\?|$)/i.test(clean)) {
    return `<script src="${clean}" defer></script>`
  }
  if (/\.(woff2?|woff|ttf|otf|eot)(\?|$)/i.test(clean)) {
    const ext = (clean.split('.').pop() || '').toLowerCase()
    const fontMimeMap = {
      woff2: 'font/woff2',
      woff: 'font/woff',
      ttf: 'font/ttf',
      otf: 'font/otf',
      eot: 'application/vnd.ms-fontobject'
    }
    const mime = fontMimeMap[ext] || 'font/woff2'
    return `<link rel="preload" href="${clean}" as="font" type="${mime}" crossorigin>`
  }
  return `<link rel="preload" href="${clean}" as="fetch">`
}

async function run() {
  const navTimeout = parseInt(process.env.TECHSCAN_NAV_TIMEOUT || '0', 10)
  const full = process.env.TECHSCAN_FULL === '1'
  const blockResourcesEnv = process.env.TECHSCAN_BLOCK_RESOURCES
  // Blocking logic:
  //  - If TECHSCAN_BLOCK_RESOURCES=0 => never block
  //  - If =1 => always block (even for full)
  //  - If unset => block only for fast (non-full) mode (previous default)
  const shouldBlock = blockResourcesEnv === '0' ? false : (blockResourcesEnv === '1' ? true : (!full))
  // Allow custom resource types list (comma separated) else default
  const customTypes = (process.env.TECHSCAN_BLOCK_RESOURCE_TYPES || '').split(',').map(s => s.trim()).filter(Boolean)
  const blockTypes = customTypes.length ? customTypes : ['image', 'media', 'font']
  // Optional size threshold in KB (abort images/media larger than this)
  let sizeThresholdKB = 0
  if (process.env.TECHSCAN_BLOCK_MAX_KB) {
    const v = parseInt(process.env.TECHSCAN_BLOCK_MAX_KB, 10)
    if (!isNaN(v) && v > 0) sizeThresholdKB = v
  }
  const baseWait = full ? 15000 : 10000
  const maxWait = navTimeout && navTimeout > 0 ? navTimeout : baseWait
  const options = {
    debug: false,
    delay: full ? 100 : 50,
    headers: {},
    maxDepth: full ? 2 : 1,
    maxUrls: 1,
    maxWait, // wappalyzer internal wait (ms)
    recursive: false,
    probe: true,
    extended: true,
    userAgent: 'Mozilla/5.0 (TechScan)'
  }
  const wappalyzer = new Wappalyzer(options)
  await wappalyzer.init()
  try {
    const site = await wappalyzer.open(url)
    // Optional light interaction to trigger late-loading tags/ads
    try {
      const page = await getPrimaryPage(site)
      if (page && process.env.TECHSCAN_INTERACT === '1') {
        await page.waitForTimeout(1200)
        await page.evaluate(() => {
          try { window.scrollBy(0, window.innerHeight * 0.8) } catch { }
          try { window.scrollBy(0, window.innerHeight * 0.8) } catch { }
        })
        await page.waitForTimeout(800)
      }
    } catch (ie) {
      if (process.env.TECHSCAN_DEBUG) console.error('[techscan] interaction step failed:', ie.message || String(ie))
    }
    if (shouldBlock) {
      // Attempt to block heavy resource types if underlying driver exposes a page object
      try {
        const page = await getPrimaryPage(site)
        if (page && !page._techscanInterception) {
          await page.setRequestInterception(true)
          page.on('request', req => {
            try {
              const type = req.resourceType()
              if (blockTypes.includes(type)) return req.abort()
            } catch { }
            req.continue()
          })
          if (sizeThresholdKB > 0) {
            try {
              page.on('response', async resp => {
                try {
                  const req = resp.request()
                  if (!req) return
                  const type = req.resourceType()
                  if (!['image', 'media'].includes(type)) return
                  const lenH = resp.headers()['content-length']
                  if (lenH) {
                    const bytes = parseInt(lenH, 10)
                    if (!isNaN(bytes) && bytes / 1024 > sizeThresholdKB) {
                      try { req.abort() } catch { }
                    }
                  }
                } catch { }
              })
            } catch { }
          }
          page._techscanInterception = true
        }
      } catch (e) {
        if (process.env.TECHSCAN_DEBUG) {
          console.error('[techscan] interception setup failed:', e.message || String(e))
        }
      }
    }
    const results = await site.analyze()
    const patterns = results.patterns || {}
    // Normalize categories -> names array of strings
    const evidenceFromPatterns = {}
    Object.entries(patterns).forEach(([techName, arr]) => {
      if (!Array.isArray(arr)) return
      evidenceFromPatterns[techName] = arr.map(item => {
        const value = typeof item.value === 'string' ? item.value : null
        const conf = Number(item.confidence)
        const ev = {
          kind: 'pattern',
          source: item.type || null,
          pattern: item.regex || null,
          match: item.match || null,
          value,
          confidence: Number.isFinite(conf) ? conf : null,
          version: item.version || null,
          implies: Array.isArray(item.implies) && item.implies.length ? item.implies : undefined,
          excludes: Array.isArray(item.excludes) && item.excludes.length ? item.excludes : undefined
        }
        if (value && /^https?:\/\//i.test(value)) {
          ev.url = value
          ev.snippet = inferSnippetFromUrl(value)
        }
        return ev
      })
    })
    const techs = (results.technologies || []).map(t => ({
      name: t.name,
      version: t.version || null,
      categories: (t.categories || []).map(c => c.name || c),
      confidence: t.confidence || null,
      evidence: evidenceFromPatterns[t.name] || []
    }))

    // Synthetic GA4 detection (look for gtag/js?id=G- or measurement prefix in scripts/source)
    try {
      if (!techs.find(t => t.name === 'GA4')) {
        const page = await getPrimaryPage(site)
        if (page) {
          const scripts = await page.$$eval('script', nodes => nodes.map(n => n.src || n.innerHTML || ''))
          const hasGA4 = scripts.some(s => /G-[A-Z0-9]{4,}/.test(s))
          if (hasGA4) {
            techs.push({ name: 'GA4', version: null, categories: ['Analytics'], confidence: 50, evidence: [] })
          }
          // Synthetic jQuery / jQuery UI / TinyMCE
          try {
            const detection = await page.evaluate(() => {
              const out = {}
              // jQuery core
              if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
                out.jqueryVersion = window.jQuery.fn.jquery
              } else if (window.$ && window.$.fn && window.$.fn.jquery) {
                out.jqueryVersion = window.$.fn.jquery
              }
              // jQuery UI
              if (window.jQuery && window.jQuery.ui && window.jQuery.ui.version) {
                out.jqueryUiVersion = window.jQuery.ui.version
              } else if (window.$ && window.$.ui && window.$.ui.version) {
                out.jqueryUiVersion = window.$.ui.version
              }
              // jQuery Migrate
              if (window.jQuery && window.jQuery.migrateVersion) {
                out.jqueryMigrateVersion = window.jQuery.migrateVersion
              } else if (window.$ && window.$.migrateVersion) {
                out.jqueryMigrateVersion = window.$.migrateVersion
              }
              // TinyMCE 4/5+ exposes tinymce.majorVersion/minorVersion; v3 exposes tinyMCE.majorVersion
              if (window.tinymce && window.tinymce.majorVersion) {
                const mv = window.tinymce.majorVersion
                const minv = window.tinymce.minorVersion || ''
                out.tinymceVersion = (mv + (minv ? '.' + minv : '')).replace(/\.$/, '')
              } else if (window.tinyMCE && window.tinyMCE.majorVersion) {
                const mv = window.tinyMCE.majorVersion
                const minv = window.tinyMCE.minorVersion || ''
                out.tinymceVersion = (mv + (minv ? '.' + minv : '')).replace(/\.$/, '')
              }
              return out
            })
            if (detection.jqueryVersion && !techs.find(t => t.name === 'jQuery')) {
              techs.push({ name: 'jQuery', version: detection.jqueryVersion, categories: ['JavaScript libraries'], confidence: 60, evidence: [] })
            }
            if (detection.jqueryUiVersion && !techs.find(t => t.name === 'jQuery UI')) {
              techs.push({ name: 'jQuery UI', version: detection.jqueryUiVersion, categories: ['JavaScript libraries'], confidence: 50, evidence: [] })
            }
            if (detection.jqueryMigrateVersion && !techs.find(t => t.name === 'jQuery Migrate')) {
              techs.push({ name: 'jQuery Migrate', version: detection.jqueryMigrateVersion, categories: ['JavaScript libraries'], confidence: 50, evidence: [] })
            }
            if (detection.tinymceVersion && !techs.find(t => t.name.toLowerCase() === 'tinymce')) {
              techs.push({ name: 'TinyMCE', version: detection.tinymceVersion, categories: ['Rich text editors'], confidence: 55, evidence: [] })
            }
          } catch (se) {
            if (process.env.TECHSCAN_DEBUG) console.error('[techscan] synthetic jQuery/TinyMCE detection failed:', se.message || String(se))
          }

          // Tailwind CSS synthetic detection (optional)
          if (process.env.TECHSCAN_SYNTHETIC_TAILWIND !== '0' && !techs.find(t => t.name === 'Tailwind CSS')) {
            try {
              const tailwindData = await page.evaluate(() => {
                const result = { cdn: false, heuristic: false, density: 0, hits: 0, total: 0, distinctPrefixes: 0, bodyFlag: false }
                const linkOrScript = Array.from(document.querySelectorAll('link[href],script[src]')).some(n => /tailwind/i.test(n.getAttribute('href') || n.getAttribute('src') || ''))
                if (linkOrScript) result.cdn = true
                try {
                  if (document.body && /tailwind/i.test(document.body.className || '')) result.bodyFlag = true
                } catch { }
                const classElems = Array.from(document.querySelectorAll('[class]'))
                let hits = 0; let total = 0; const prefixSet = new Set()
                const utilRe = /^(?:sm:|md:|lg:|xl:|2xl:|dark:)?(?:p[trblxy]?-[0-9]+|m[trblxy]?-[0-9]+|bg-[a-z0-9-:\/]+|text-[a-z0-9-:\/]+|flex|grid|inline-flex|hidden|block|inline-block|items-[a-z-]+|justify-[a-z-]+|gap-[0-9]+|w-[0-9\/]+|h-[0-9\/]+|rounded(?:-[a-z0-9]+)?|shadow(?:-[a-z0-9]+)?|aspect-[a-z0-9/]+|place-[a-z-]+|top-[0-9]+|left-[0-9]+|right-[0-9]+|bottom-[0-9]+|translate-[xy]-[0-9]+)/
                for (const el of classElems) {
                  const tokens = el.className.split(/\s+/).filter(Boolean)
                  for (const tok of tokens) {
                    total++
                    if (utilRe.test(tok)) {
                      hits++
                      const core = tok.replace(/^(sm:|md:|lg:|xl:|2xl:|dark:)/, '').split('-')[0]
                      prefixSet.add(core)
                    }
                  }
                  if (total > 4000) break // safety cap
                }
                result.hits = hits
                result.total = total
                result.density = total ? hits / total : 0
                result.distinctPrefixes = prefixSet.size
                if (result.cdn || result.bodyFlag || (hits >= 10 && result.density > 0.18 && prefixSet.size >= 4)) {
                  result.heuristic = true
                }
                return result
              })
              if (tailwindData && (tailwindData.cdn || tailwindData.heuristic)) {
                techs.push({ name: 'Tailwind CSS', version: null, categories: ['CSS frameworks'], confidence: tailwindData.cdn ? 65 : 55, evidence: [] })
              }
            } catch (te) {
              if (process.env.TECHSCAN_DEBUG) console.error('[techscan] Tailwind detection failed:', te.message || String(te))
            }
          }

          // DoubleClick Floodlight synthetic detection
          if (process.env.TECHSCAN_SYNTHETIC_FLOODLIGHT !== '0' && !techs.find(t => t.name === 'Floodlight' || t.name === 'DoubleClick Floodlight')) {
            try {
              const floodlight = await page.evaluate(() => {
                const urls = []
                const texts = []
                document.querySelectorAll('script[src],img[src],iframe[src]').forEach(n => {
                  const u = n.getAttribute('src') || ''
                  if (/fls\.doubleclick\.net/i.test(u) || /googleads\.g\.doubleclick\.net\/pagead\/viewthroughconversion/i.test(u)) {
                    urls.push(u)
                  }
                })
                // Inline script scan for Floodlight markers (ord=, fls.doubleclick.net, dc_pre, floodlight)
                document.querySelectorAll('script:not([src])').forEach(s => {
                  const txt = s.textContent || ''
                  if (/fls\.doubleclick\.net/i.test(txt) || /floodlight/i.test(txt) || /dc_pre/i.test(txt) || /DC-[A-Z0-9]{3,}/i.test(txt)) {
                    texts.push(txt.slice(0, 500))
                  }
                })
                return { urls, texts }
              })
              const urlHits = floodlight && floodlight.urls && floodlight.urls.length
              const textHits = floodlight && floodlight.texts && floodlight.texts.length
              if (urlHits || textHits) {
                techs.push({ name: 'Floodlight', version: null, categories: ['Advertising'], confidence: urlHits ? 55 : 50, evidence: [] })
              }
            } catch (fe) {
              if (process.env.TECHSCAN_DEBUG) console.error('[techscan] Floodlight DOM detection failed:', fe.message || String(fe))
            }
          }

          // --- Version enrichment heuristics ---
          try {
            const versionHints = await page.evaluate(() => {
              const out = { metaGenerator: null, wpVer: null, assetVersions: [] }
              try {
                const mg = document.querySelector('meta[name="generator"]')
                if (mg) out.metaGenerator = (mg.getAttribute('content') || '').trim()
              } catch { }
              // Capture ?ver= or v= query params in common script/link assets
              try {
                const assets = []
                document.querySelectorAll('link[href],script[src]').forEach(n => {
                  const href = n.getAttribute('href') || n.getAttribute('src') || ''
                  if (!href) return
                  const m = href.match(/[?&](?:ver|v)=([0-9]{1,3}(?:\.[0-9]{1,3}){0,3})/i)
                  if (m) assets.push(m[1])
                })
                out.assetVersions = assets.slice(0, 20)
              } catch { }
              return out
            })
            if (versionHints) {
              // WordPress from meta generator e.g. "WordPress 6.4.2"
              if (versionHints.metaGenerator && /wordpress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.test(versionHints.metaGenerator)) {
                const m = versionHints.metaGenerator.match(/wordpress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)
                if (m) {
                  const wpVersion = m[1]
                  const existing = techs.find(t => t.name === 'WordPress')
                  if (existing && !existing.version) existing.version = wpVersion
                }
              }
              // If many asset ?ver= share same version and a tech lacks version, attempt weak fill (skip if already have version)
              if (versionHints.assetVersions && versionHints.assetVersions.length) {
                const freq = {}
                versionHints.assetVersions.forEach(v => { freq[v] = (freq[v] || 0) + 1 })
                const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1])
                if (sorted.length && sorted[0][1] >= 2) {
                  const common = sorted[0][0]
                  // Fill popular CMS or library placeholders without versions
                  const candidateNames = ['WordPress', 'WooCommerce', 'Elementor', 'jQuery']
                  candidateNames.forEach(name => {
                    const t = techs.find(tt => tt.name === name)
                    if (t && !t.version) t.version = common
                  })
                }
              }
            }
          } catch (ve) {
            if (process.env.TECHSCAN_DEBUG) console.error('[techscan] version enrichment failed:', ve.message || String(ve))
          }
        }
      }
    } catch (e) {
      if (process.env.TECHSCAN_DEBUG) console.error('[techscan] GA4 synthetic detection failed:', e.message || String(e))
    }
    // Synthetic YouTube / Polymer SPA detection (optional)
    if (process.env.TECHSCAN_SYNTHETIC_YOUTUBE !== '0' && !techs.find(t => t.name === 'YouTube Platform')) {
      try {
        const page = await getPrimaryPage(site)
        if (page) {
          const yt = await page.evaluate(() => {
            const out = { ytcfg: false, polymer: false, ytPlayer: false, scripts: 0 }
            try {
              if (window.ytcfg && typeof window.ytcfg.get === 'function') out.ytcfg = true
            } catch { }
            try {
              if (window.Polymer || (window.webcomponents && window.webcomponents.readyTime)) out.polymer = true
            } catch { }
            try {
              if (window.ytplayer || window.yt) out.ytPlayer = true
            } catch { }
            try {
              out.scripts = document.querySelectorAll('script').length
            } catch { }
            return out
          })
          const strong = yt && (yt.ytcfg && yt.ytPlayer)
          const moderate = yt && (yt.ytcfg || yt.ytPlayer) && yt.polymer
          if (strong || moderate) {
            techs.push({
              name: 'YouTube Platform',
              version: null,
              categories: ['Video platforms', 'CDN'],
              confidence: strong ? 80 : 55,
              evidence: []
            })
          }
        }
      } catch (ye) {
        if (process.env.TECHSCAN_DEBUG) console.error('[techscan] YouTube synthetic detection failed:', ye.message || String(ye))
      }
    }
    // Generic SPA detection (React / Vue / Angular) optional
    if (process.env.TECHSCAN_SYNTHETIC_SPA !== '0') {
      try {
        const page = await getPrimaryPage(site)
        if (page) {
          const spa = await page.evaluate(() => {
            const out = { react: false, reactVersion: null, vue: false, vueVersion: null, angular: false, angularVersion: null }
            try {
              // React detection: look for __REACT_DEVTOOLS_GLOBAL_HOOK__ or React dev attributes
              if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) out.react = true
              // Try to infer version from preloaded data (heuristic: search script text)
              const scripts = Array.from(document.querySelectorAll('script')).map(s => s.innerHTML || '')
              for (const src of scripts.slice(0, 20)) {
                const m = src.match(/react@([0-9]+\.[0-9]+\.[0-9]+)/i)
                if (m) { out.reactVersion = m[1]; break }
              }
            } catch { }
            try {
              if (window.Vue || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) out.vue = true
              if (window.Vue && window.Vue.version) out.vueVersion = window.Vue.version
            } catch { }
            try {
              // Angular: presence of ng-version attribute or window.ng.coreTokens
              const ngRoot = document.querySelector('[ng-version]')
              if (ngRoot) { out.angular = true; out.angularVersion = ngRoot.getAttribute('ng-version') }
              if (!out.angular && window.ng && window.ng.coreTokens) out.angular = true
            } catch { }
            return out
          })
          // React
          if (spa.react && process.env.TECHSCAN_SYNTHETIC_REACT !== '0' && !techs.find(t => t.name === 'React')) {
            techs.push({ name: 'React', version: spa.reactVersion || null, categories: ['JavaScript frameworks'], confidence: spa.reactVersion ? 70 : 55, evidence: [] })
          }
          // Vue
          if (spa.vue && process.env.TECHSCAN_SYNTHETIC_VUE !== '0' && !techs.find(t => t.name === 'Vue.js' || t.name === 'Vue')) {
            techs.push({ name: 'Vue.js', version: spa.vueVersion || null, categories: ['JavaScript frameworks'], confidence: spa.vueVersion ? 70 : 55, evidence: [] })
          }
          // Angular
          if (spa.angular && process.env.TECHSCAN_SYNTHETIC_ANGULAR !== '0' && !techs.find(t => t.name === 'Angular')) {
            techs.push({ name: 'Angular', version: spa.angularVersion || null, categories: ['JavaScript frameworks'], confidence: spa.angularVersion ? 70 : 55, evidence: [] })
          }
        }
      } catch (se) {
        if (process.env.TECHSCAN_DEBUG) console.error('[techscan] SPA synthetic detection failed:', se.message || String(se))
      }
    }
    const hintMeta = await collectHintMeta(site)
    const extras = await collectExtras(site)
    if (process.env.TECHSCAN_CUSTOM_SIGNATURES !== '0') {
      try {
        const customAdds = applyCustomSignatures({ extras, hintMeta, techs, signatures: CUSTOM_SIGNATURES })
        if (customAdds && customAdds.length) {
          techs.push(...customAdds)
        }
      } catch (err) {
        if (process.env.TECHSCAN_DEBUG) {
          console.error('[techscan] custom signatures application failed:', err.message || String(err))
        }
      }
    }
    const categories = {}
    for (const t of techs) {
      for (const c of t.categories) {
        if (!categories[c]) categories[c] = []
        categories[c].push({ name: t.name, version: t.version })
      }
    }
    const out = {
      url: results.url || url,
      technologies: techs,
      categories,
      scan_mode: full ? 'full' : 'fast'
    }
    if (patterns && Object.keys(patterns).length) {
      out.patterns = patterns
    }
    if (hintMeta && Object.keys(hintMeta).length) {
      out._techscan_hint_meta = hintMeta
    }
    if (extras && Object.keys(extras).length) {
      out.extras = extras
    }
    process.stdout.write(JSON.stringify(out))
  } catch (e) {
    console.error(e.message || String(e))
    process.exit(2)
  } finally {
    try { await wappalyzer.destroy() } catch { }
  }
}

run()
