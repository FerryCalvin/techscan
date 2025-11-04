#!/usr/bin/env node
// Lightweight wrapper to scan a single domain and print normalized JSON.
// Adds Windows Chrome/Edge executable auto-detection so you can set PUPPETEER_SKIP_DOWNLOAD=1 during install.
import fs from 'fs'
import path from 'path'
import Wappalyzer from 'wappalyzer'

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
  const customTypes = (process.env.TECHSCAN_BLOCK_RESOURCE_TYPES || '').split(',').map(s=>s.trim()).filter(Boolean)
  const blockTypes = customTypes.length ? customTypes : ['image','media','font','stylesheet']
  // Optional size threshold in KB (abort images/media larger than this)
  let sizeThresholdKB = 0
  if (process.env.TECHSCAN_BLOCK_MAX_KB) {
    const v = parseInt(process.env.TECHSCAN_BLOCK_MAX_KB,10)
    if (!isNaN(v) && v>0) sizeThresholdKB = v
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
    userAgent: 'Mozilla/5.0 (TechScan)'
  }
  const wappalyzer = new Wappalyzer(options)
  await wappalyzer.init()
  try {
    const site = await wappalyzer.open(url)
    if (shouldBlock) {
      // Attempt to block heavy resource types if underlying driver exposes a page object
      try {
        const page = site.driver && site.driver.browser && site.driver.browser.pages ? (await site.driver.browser.pages())[0] : null
        if (page && !page._techscanInterception) {
          await page.setRequestInterception(true)
          page.on('request', req => {
            try {
              const type = req.resourceType()
              if (blockTypes.includes(type)) return req.abort()
            } catch {}
            req.continue()
          })
          if (sizeThresholdKB > 0) {
            try {
              page.on('response', async resp => {
                try {
                  const req = resp.request()
                  if (!req) return
                  const type = req.resourceType()
                  if (!['image','media'].includes(type)) return
                  const lenH = resp.headers()['content-length']
                  if (lenH) {
                    const bytes = parseInt(lenH,10)
                    if (!isNaN(bytes) && bytes/1024 > sizeThresholdKB) {
                      try { req.abort() } catch {}
                    }
                  }
                } catch {}
              })
            } catch {}
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
    // Normalize categories -> names array of strings
    const techs = (results.technologies || []).map(t => ({
      name: t.name,
      version: t.version || null,
      categories: (t.categories || []).map(c => c.name || c),
      confidence: t.confidence || null
    }))

    // Synthetic GA4 detection (look for gtag/js?id=G- or measurement prefix in scripts/source)
    try {
      if (!techs.find(t => t.name === 'GA4')) {
        const page = site.driver && site.driver.browser && site.driver.browser.pages ? (await site.driver.browser.pages())[0] : null
        if (page) {
          const scripts = await page.$$eval('script', nodes => nodes.map(n => n.src || n.innerHTML || ''))
          const hasGA4 = scripts.some(s => /G-[A-Z0-9]{4,}/.test(s))
          if (hasGA4) {
            techs.push({ name: 'GA4', version: null, categories: ['Analytics'], confidence: 50 })
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
              techs.push({ name: 'jQuery', version: detection.jqueryVersion, categories: ['JavaScript libraries'], confidence: 60 })
            }
            if (detection.jqueryUiVersion && !techs.find(t => t.name === 'jQuery UI')) {
              techs.push({ name: 'jQuery UI', version: detection.jqueryUiVersion, categories: ['JavaScript libraries'], confidence: 50 })
            }
            if (detection.tinymceVersion && !techs.find(t => t.name.toLowerCase() === 'tinymce')) {
              techs.push({ name: 'TinyMCE', version: detection.tinymceVersion, categories: ['Rich text editors'], confidence: 55 })
            }
          } catch (se) {
            if (process.env.TECHSCAN_DEBUG) console.error('[techscan] synthetic jQuery/TinyMCE detection failed:', se.message || String(se))
          }

          // Tailwind CSS synthetic detection (optional)
          if (process.env.TECHSCAN_SYNTHETIC_TAILWIND !== '0' && !techs.find(t => t.name === 'Tailwind CSS')) {
            try {
              const tailwindData = await page.evaluate(() => {
                const result = { cdn: false, heuristic: false, density: 0, hits: 0, total: 0, distinctPrefixes: 0 }
                const linkOrScript = Array.from(document.querySelectorAll('link[href],script[src]')).some(n => /tailwind/i.test(n.getAttribute('href') || n.getAttribute('src') || ''))
                if (linkOrScript) result.cdn = true
                const classElems = Array.from(document.querySelectorAll('[class]'))
                let hits = 0; let total = 0; const prefixSet = new Set()
                const utilRe = /^(?:sm:|md:|lg:|xl:|2xl:|dark:)?(?:p[trblxy]?-[0-9]+|m[trblxy]?-[0-9]+|bg-[a-z0-9-:\/]+|text-[a-z0-9-:\/]+|flex|grid|inline-flex|hidden|block|inline-block|items-[a-z-]+|justify-[a-z-]+|gap-[0-9]+|w-[0-9\/]+|h-[0-9\/]+|rounded(?:-[a-z0-9]+)?|shadow(?:-[a-z0-9]+)?)/
                for (const el of classElems) {
                  const tokens = el.className.split(/\s+/).filter(Boolean)
                  for (const tok of tokens) {
                    total++
                    if (utilRe.test(tok)) {
                      hits++
                      const core = tok.replace(/^(sm:|md:|lg:|xl:|2xl:|dark:)/,'').split('-')[0]
                      prefixSet.add(core)
                    }
                  }
                  if (total > 4000) break // safety cap
                }
                result.hits = hits
                result.total = total
                result.density = total ? hits / total : 0
                result.distinctPrefixes = prefixSet.size
                if (result.cdn || (hits >= 30 && result.density > 0.35 && prefixSet.size >= 8)) {
                  result.heuristic = true
                }
                return result
              })
              if (tailwindData && (tailwindData.cdn || tailwindData.heuristic)) {
                techs.push({ name: 'Tailwind CSS', version: null, categories: ['CSS frameworks'], confidence: tailwindData.cdn ? 65 : 55 })
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
                document.querySelectorAll('script[src],img[src],iframe[src]').forEach(n => {
                  const u = n.getAttribute('src') || ''
                  if (/fls\.doubleclick\.net\/activity/i.test(u)) urls.push(u)
                })
                return urls
              })
              if (floodlight && floodlight.length) {
                techs.push({ name: 'Floodlight', version: null, categories: ['Advertising'], confidence: 50 })
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
              } catch {}
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
              } catch {}
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
                versionHints.assetVersions.forEach(v => { freq[v] = (freq[v]||0)+1 })
                const sorted = Object.entries(freq).sort((a,b)=>b[1]-a[1])
                if (sorted.length && sorted[0][1] >= 2) {
                  const common = sorted[0][0]
                  // Fill popular CMS or library placeholders without versions
                  const candidateNames = ['WordPress','WooCommerce','Elementor','jQuery']
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
        const page = site.driver && site.driver.browser && site.driver.browser.pages ? (await site.driver.browser.pages())[0] : null
        if (page) {
          const yt = await page.evaluate(() => {
            const out = { ytcfg: false, polymer: false, ytPlayer: false, scripts: 0 }
            try {
              if (window.ytcfg && typeof window.ytcfg.get === 'function') out.ytcfg = true
            } catch {}
            try {
              if (window.Polymer || (window.webcomponents && window.webcomponents.readyTime)) out.polymer = true
            } catch {}
            try {
              if (window.ytplayer || window.yt) out.ytPlayer = true
            } catch {}
            try {
              out.scripts = document.querySelectorAll('script').length
            } catch {}
            return out
          })
          const strong = yt && (yt.ytcfg && yt.ytPlayer)
          const moderate = yt && (yt.ytcfg || yt.ytPlayer) && yt.polymer
          if (strong || moderate) {
            techs.push({
              name: 'YouTube Platform',
              version: null,
              categories: ['Video platforms','CDN'],
              confidence: strong ? 80 : 55
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
        const page = site.driver && site.driver.browser && site.driver.browser.pages ? (await site.driver.browser.pages())[0] : null
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
            } catch {}
            try {
              if (window.Vue || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) out.vue = true
              if (window.Vue && window.Vue.version) out.vueVersion = window.Vue.version
            } catch {}
            try {
              // Angular: presence of ng-version attribute or window.ng.coreTokens
              const ngRoot = document.querySelector('[ng-version]')
              if (ngRoot) { out.angular = true; out.angularVersion = ngRoot.getAttribute('ng-version') }
              if (!out.angular && window.ng && window.ng.coreTokens) out.angular = true
            } catch {}
            return out
          })
          // React
          if (spa.react && process.env.TECHSCAN_SYNTHETIC_REACT !== '0' && !techs.find(t => t.name === 'React')) {
            techs.push({ name: 'React', version: spa.reactVersion || null, categories: ['JavaScript frameworks'], confidence: spa.reactVersion ? 70 : 55 })
          }
            // Vue
          if (spa.vue && process.env.TECHSCAN_SYNTHETIC_VUE !== '0' && !techs.find(t => t.name === 'Vue.js' || t.name === 'Vue')) {
            techs.push({ name: 'Vue.js', version: spa.vueVersion || null, categories: ['JavaScript frameworks'], confidence: spa.vueVersion ? 70 : 55 })
          }
          // Angular
          if (spa.angular && process.env.TECHSCAN_SYNTHETIC_ANGULAR !== '0' && !techs.find(t => t.name === 'Angular')) {
            techs.push({ name: 'Angular', version: spa.angularVersion || null, categories: ['JavaScript frameworks'], confidence: spa.angularVersion ? 70 : 55 })
          }
        }
      } catch (se) {
        if (process.env.TECHSCAN_DEBUG) console.error('[techscan] SPA synthetic detection failed:', se.message || String(se))
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
    process.stdout.write(JSON.stringify(out))
  } catch (e) {
    console.error(e.message || String(e))
    process.exit(2)
  } finally {
    try { await wappalyzer.destroy() } catch {}
  }
}

run()
