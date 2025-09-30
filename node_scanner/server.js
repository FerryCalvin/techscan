#!/usr/bin/env node
// Persistent scanning daemon: reuse one Puppeteer browser for multiple scans.
// Protocol: newline-delimited JSON commands on stdin; each response is one JSON line to stdout.
// Command shape: {"id":"uuid","cmd":"scan","url":"example.com","full":false}
// Response shape: {"id":"uuid","ok":true,"result":{...}} or {"id":"uuid","ok":false,"error":"..."}

import fs from 'fs'
import readline from 'readline'
import Wappalyzer from 'wappalyzer'

const MAX_PAGES = parseInt(process.env.TECHSCAN_MAX_PAGES || '6', 10)
let browserInstance = null
let wappalyzerInstance = null
let activeScans = 0
let totalScans = 0
let lastRestart = Date.now()
const RECYCLE_AFTER = parseInt(process.env.TECHSCAN_BROWSER_RECYCLE || '250', 10)
const DEBUG = !!process.env.TECHSCAN_DEBUG

async function init() {
  if (wappalyzerInstance) return
  const options = {
    debug: false,
    delay: 50,
    maxDepth: 1,
    maxUrls: 1,
    maxWait: 10000,
    probe: true,
    userAgent: 'Mozilla/5.0 (TechScan-Persist)'
  }
  wappalyzerInstance = new Wappalyzer(options)
  await wappalyzerInstance.init()
  browserInstance = wappalyzerInstance.driver?.browser
  if (DEBUG) process.stderr.write('[daemon] initialized browser\n')
}

async function destroy() {
  try { if (wappalyzerInstance) await wappalyzerInstance.destroy() } catch {}
  wappalyzerInstance = null
  browserInstance = null
}

async function recycleIfNeeded() {
  if (totalScans >= RECYCLE_AFTER) {
    if (DEBUG) process.stderr.write('[daemon] recycling browser after scans=' + totalScans + '\n')
    await destroy()
    await init()
    totalScans = 0
    lastRestart = Date.now()
  }
}

async function performScan(targetUrl, full) {
  await init()
  // Adjust dynamic options: for full scans we increase wait & depth
  if (full) {
    wappalyzerInstance.options.maxDepth = 2
    wappalyzerInstance.options.maxWait = 15000
    wappalyzerInstance.options.delay = 100
  } else {
    wappalyzerInstance.options.maxDepth = 1
    wappalyzerInstance.options.maxWait = 8000
    wappalyzerInstance.options.delay = 50
  }
  const navTimeout = parseInt(process.env.TECHSCAN_NAV_TIMEOUT || '0', 10)
  if (navTimeout > 0) {
    wappalyzerInstance.options.maxWait = Math.min(wappalyzerInstance.options.maxWait, navTimeout)
  }
  // Block heavy resources for non-full
  try {
    if (!full) {
      const pages = await browserInstance.pages()
      if (pages.length) {
        const page = pages[0]
        if (!page._techscanInterception) {
          await page.setRequestInterception(true)
          page.on('request', req => {
            const type = req.resourceType()
            if (['image','media','font','stylesheet'].includes(type)) return req.abort()
            req.continue()
          })
          page._techscanInterception = true
        }
      }
    }
  } catch {}
  const site = await wappalyzerInstance.open(targetUrl)
  // If page object accessible, set default navigation timeout
  try {
    if (navTimeout > 0 && site.driver && site.driver.page && site.driver.page.setDefaultNavigationTimeout) {
      site.driver.page.setDefaultNavigationTimeout(navTimeout)
    }
  } catch {}
  const results = await site.analyze()
  const techs = (results.technologies || []).map(t => ({
    name: t.name,
    version: t.version || null,
    categories: (t.categories || []).map(c => c.name || c),
    confidence: t.confidence || null
  }))
  const categories = {}
  for (const t of techs) {
    for (const c of t.categories) {
      if (!categories[c]) categories[c] = []
      categories[c].push({ name: t.name, version: t.version })
    }
  }
  totalScans++
  await recycleIfNeeded()
  return { url: results.url || targetUrl, technologies: techs, categories, scan_mode: full ? 'full' : 'fast', engine: 'wappalyzer-persist' }
}

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) return 'https://' + input
  return input
}

async function handleMessage(msg) {
  if (msg.cmd === 'scan') {
    const url = normalizeUrl(msg.url)
    try {
      activeScans++
      const t0 = Date.now()
      const result = await performScan(url, !!msg.full)
      const elapsed = (Date.now() - t0) / 1000
      result.duration = elapsed
      process.stdout.write(JSON.stringify({ id: msg.id, ok: true, result }) + '\n')
    } catch (e) {
      process.stdout.write(JSON.stringify({ id: msg.id, ok: false, error: e.message || String(e) }) + '\n')
    } finally {
      activeScans--
    }
  } else if (msg.cmd === 'ping') {
    process.stdout.write(JSON.stringify({ id: msg.id, ok: true, pong: true, activeScans, totalScans, lastRestart }) + '\n')
  } else if (msg.cmd === 'shutdown') {
    await destroy()
    process.stdout.write(JSON.stringify({ id: msg.id, ok: true, shutdown: true }) + '\n')
    process.exit(0)
  } else {
    process.stdout.write(JSON.stringify({ id: msg.id, ok: false, error: 'unknown cmd' }) + '\n')
  }
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
rl.on('line', line => {
  if (!line.trim()) return
  try {
    const msg = JSON.parse(line)
    handleMessage(msg)
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: 'bad_json' }) + '\n')
  }
})

process.on('SIGINT', async () => { await destroy(); process.exit(0) })
process.on('SIGTERM', async () => { await destroy(); process.exit(0) })
