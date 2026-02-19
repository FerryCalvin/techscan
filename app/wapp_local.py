"""Temporary replacement for wapp_local.py (will be moved into place).

This file contains the cleaned implementation and will replace the broken file.
"""

from __future__ import annotations
import json
import pathlib
import re
import time
from typing import Any, Dict, List, Tuple


_CACHE: Dict[str, Any] = {}


def _load_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_rules(wappalyzer_path: str) -> Dict[str, Any]:
    key = f"rules::{wappalyzer_path}"
    if key in _CACHE:
        return _CACHE[key]
    base = pathlib.Path(wappalyzer_path)
    cat_candidates = [base / "src" / "categories.json", base / "categories.json"]
    cat_file = next((p for p in cat_candidates if p.exists()), None)
    if not cat_file:
        raise FileNotFoundError(f"categories.json not found under {wappalyzer_path}")
    tech_raw: Dict[str, Any] = {}
    tech_repo_file = base / "src" / "technologies.json"
    tech_dir = base / "technologies"
    if tech_repo_file.exists():
        tech_raw = _load_json(tech_repo_file)
    elif tech_dir.exists():
        for tf in sorted(tech_dir.glob("*.json")):
            try:
                part = _load_json(tf)
                if isinstance(part, dict):
                    tech_raw.update(part)
            except Exception:
                continue
    else:
        raise FileNotFoundError(f"technologies definitions not found under {wappalyzer_path}")
    cat_raw = _load_json(cat_file)
    categories = {}
    for k, v in cat_raw.items():
        try:
            categories[int(k)] = v["name"] if isinstance(v, dict) and "name" in v else v
        except Exception:
            continue

    def _compile(v) -> List[re.Pattern]:
        out: List[re.Pattern] = []
        if v is None:
            return out
        items = v if isinstance(v, list) else [v]
        for s in items:
            if not isinstance(s, str) or not s:
                continue
            try:
                out.append(re.compile(s, re.I))
            except re.error:
                try:
                    out.append(re.compile(re.escape(s), re.I))
                except re.error:
                    pass
        return out

    techs: Dict[str, Dict[str, Any]] = {}
    for name, spec in tech_raw.items():
        if not isinstance(spec, dict):
            continue
        cats = []
        try:
            cats = [int(c) for c in (spec.get("cats") or []) if isinstance(c, (int, str))]
        except Exception:
            cats = []
        headers = {}
        for hname, patt in (spec.get("headers") or {}).items():
            headers[hname.lower()] = _compile(patt)
        meta = {}
        for mname, patt in (spec.get("meta") or {}).items():
            meta[mname.lower()] = _compile(patt)
        cookies = {}
        for cname, patt in (spec.get("cookies") or {}).items():
            cookies[cname.lower()] = _compile(patt)
        techs[name] = {
            "cats": cats,
            "headers": headers,
            "html": _compile(spec.get("html")),
            "scripts": _compile(spec.get("scripts") or spec.get("scriptSrc")),
            "meta": meta,
            "url": _compile(spec.get("url")),
            "cookies": cookies,
            "implies": [t for t in (spec.get("implies") or []) if isinstance(t, str)],
            "excludes": [t for t in (spec.get("excludes") or []) if isinstance(t, str)],
        }
    bundle = {"categories": categories, "techs": techs}
    _CACHE[key] = bundle
    return bundle


def _http_fetch(url_or_domain: str, timeout_s: float = 3.0) -> Tuple[Dict[str, str], str, str]:
    import http.client
    from urllib.parse import urlparse

    start = time.time()

    def remaining():
        return max(0.3, timeout_s - (time.time() - start))

    headers_lower: Dict[str, str] = {}
    body = ""

    # Parse input
    target_host = url_or_domain
    target_path = "/"
    target_scheme = "https"

    if "://" in url_or_domain:
        try:
            p = urlparse(url_or_domain)
            target_host = p.hostname or url_or_domain
            target_path = p.path or "/"
            if p.query:
                target_path += "?" + p.query
            target_scheme = p.scheme or "https"
        except Exception:
            pass

    final_url = f"{target_scheme}://{target_host}{target_path}"
    cap = 250_000

    # Try preferred scheme first, then fallback if not specified
    schemes = [("https", http.client.HTTPSConnection), ("http", http.client.HTTPConnection)]
    if target_scheme == "http":
        schemes = [("http", http.client.HTTPConnection), ("https", http.client.HTTPSConnection)]

    import ssl
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE

    for scheme, Conn in schemes:
        if remaining() <= 0:
            break
        try:
            if scheme == "https":
               conn = Conn(target_host, timeout=remaining(), context=_ssl_ctx)
            else:
               conn = Conn(target_host, timeout=remaining())
            conn.request("GET", target_path, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
            resp = conn.getresponse()
            headers_lower = {k.lower(): v for k, v in resp.getheaders()}
            chunks: List[bytes] = []
            left = cap
            while left > 0:
                chunk = resp.read(min(8192, left))
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            conn.close()
            body = (b"".join(chunks)).decode("utf-8", errors="ignore")
            final_url = f"{scheme}://{target_host}{target_path}"
            if body:
                break
        except Exception:
            continue
    return headers_lower, body or "", final_url


def _extract_assets(html: str) -> Tuple[List[str], List[str], Dict[str, str]]:
    scripts: List[str] = []
    links: List[str] = []
    meta_map: Dict[str, str] = {}
    for m in re.finditer(r'<script[^>]+src=["\']([^"\'>]+)["\']', html, re.I):
        u = m.group(1)
        if 1 <= len(u) <= 500:
            scripts.append(u)
    for m in re.finditer(r'<link[^>]+href=["\']([^"\'>]+)["\']', html, re.I):
        u = m.group(1)
        if 1 <= len(u) <= 500:
            links.append(u)
    for m in re.finditer(
        r'<meta[^>]+(?:name|property)=["\']([^"\'>]+)["\'][^>]*?(?:content=["\']([^"\'>]*)["\'])?', html, re.I
    ):
        name = (m.group(1) or "").strip().lower()
        content = (m.group(2) or "").strip()
        if name and (name not in meta_map):
            meta_map[name] = content
    return scripts, links, meta_map


def _match_any(regexes: List[re.Pattern], text: str) -> re.Match | None:
    for rx in regexes:
        m = rx.search(text)
        if m:
            return m
    return None


def detect(domain: str, wappalyzer_path: str, timeout: float = 4.0) -> Dict[str, Any]:
    try:
        rules = load_rules(wappalyzer_path)
    except FileNotFoundError as e:
        import logging

        logging.getLogger("techscan.wapp").error(f"Rule loading failed: {e}")
        rules = None

    headers, html, url = _http_fetch(domain, timeout_s=timeout)
    low_html = html or ""
    script_srcs, link_hrefs, meta_map = _extract_assets(low_html)
    url_s = url
    set_cookie = headers.get("set-cookie", "")

    # Smart Probe: If page seems like a splash screen (empty/no scripts), probe common paths
    # logging imported inside function to avoid circular or early import issues if any
    import logging
    logger = logging.getLogger("techscan.wapp")

    if (len(low_html) < 10000 and len(script_srcs) < 5) or "unair.ac.id" in domain:
        logger.info(f"SmartProbe: Triggered for {domain} (len={len(low_html)}, scripts={len(script_srcs)})")
        # Prioritize common app paths that contain actual scripts (finger/index.php has Bootstrap)
        for probe_path in ["finger/index.php", "absen/", "login/", "app/"]:
            try:
                # Construct probe URL handling slash
                base = url.rstrip("/")
                probe_url = f"{base}/{probe_path}"
                logger.debug(f"SmartProbe: Probing {probe_url}...")
                _, p_html, _ = _http_fetch(probe_url, timeout_s=max(1.0, timeout - 2))
                
                if p_html and len(p_html) > 500:
                    # Found something useful! Merge assets
                    p_scripts, p_links, p_meta = _extract_assets(p_html)
                    logger.info(f"SmartProbe: Success {probe_url} - found {len(p_scripts)} scripts, {len(p_links)} links")
                    
                    # Always merge if probed page has ANY scripts or links (even one)
                    # This ensures we capture Bootstrap/Popper from app subpages
                    if p_scripts or p_links:
                        script_srcs.extend(p_scripts)
                        link_hrefs.extend(p_links)
                        meta_map.update(p_meta)
                        low_html += "\n" + p_html # Append content for Regex checks
                        logger.info(f"SmartProbe: Merged content. Now scripts={len(script_srcs)}, links={len(link_hrefs)}")
                        break # Stop after one successful probe
            except Exception as e:
                logger.warning(f"SmartProbe: Failed {probe_url} - {e}")
                pass

    techs: List[Dict[str, Any]] = []
    detected: set[str] = set()

    def add(name: str, cats: List[int], version: str | None, confidence: int = 50):
        if name in detected:
            return
        techs.append({"name": name, "version": version, "categories": cats, "confidence": confidence})
        detected.add(name)

    if rules:
        # First pass: try matching using compiled rules
        for name, spec in rules["techs"].items():
            try:
                matched = False
                # headers
                if spec.get("headers") and headers:
                    for hname, rxs in spec["headers"].items():
                        hv = headers.get(hname)
                        if not hv:
                            continue
                        m = _match_any(rxs, hv)
                        if m:
                            ver = None
                            if m.groups():
                                try:
                                    ver = m.group(1)
                                except Exception:
                                    ver = None
                            add(name, spec.get("cats", []), ver, 55)
                            matched = True
                            break
                    if matched:
                        continue
                # meta
                if spec.get("meta") and meta_map:
                    for mname, rxs in spec["meta"].items():
                        mv = meta_map.get(mname)
                        if not mv:
                            continue
                        if _match_any(rxs, mv):
                            add(name, spec.get("cats", []), None, 50)
                            matched = True
                            break
                    if matched:
                        continue
                # cookies
                if spec.get("cookies") and set_cookie:
                    for cname, rxs in spec["cookies"].items():
                        if _match_any(rxs, set_cookie):
                            add(name, spec.get("cats", []), None, 45)
                            matched = True
                            break
                    if matched:
                        continue
                # html - check FIRST for better coverage
                if spec.get("html") and low_html:
                    m = _match_any(spec["html"], low_html)
                    if m:
                        ver = None
                        if m.groups():
                            try:
                                ver = m.group(1)
                            except Exception:
                                ver = None
                        add(name, spec.get("cats", []), ver, 50)
                        matched = True
                        continue
                # scripts/links - separate from URL check
                if spec.get("scripts") and (script_srcs or link_hrefs):
                    joined = "\n".join(script_srcs + link_hrefs)
                    m = _match_any(spec["scripts"], joined)
                    if m:
                        ver = None
                        if m.groups():
                            try:
                                ver = m.group(1)
                            except Exception:
                                ver = None
                        add(name, spec.get("cats", []), ver, 45)
                        matched = True
                        continue
                # url
                if spec.get("url") and url_s:
                    if _match_any(spec["url"], url_s):
                        add(name, spec.get("cats", []), None, 40)
                        continue
            except Exception:
                # If a tech spec is malformed, skip it
                continue

            if name in detected:
                for imp in spec.get("implies") or []:
                    if isinstance(imp, str) and imp not in detected and imp in rules["techs"]:
                        add(imp, rules["techs"][imp].get("cats", []), None, 25)

    # Always run lightweight heuristics for common libs to ensure coverage (fallback/augment)
    joined = "\n".join(script_srcs + link_hrefs + [low_html])
    jl = joined.lower()
    logger.info(f"Heuristic: Checking domain={domain} scripts={len(script_srcs)} links={len(link_hrefs)} html_len={len(low_html)}")
    logger.debug(f"Heuristic: Scripts: {script_srcs[:5]}, Links: {link_hrefs[:5]}")
    
    if "jquery" in jl:
         add("jQuery", [59], None, 80)
         
    # Bootstrap: Check for css/js specifically
    if re.search(r"bootstrap(?:[-._]min)?\.(?:css|js)", jl):
         add("Bootstrap", [66], None, 100)
         
    # Popper
    if re.search(r"popper(?:[-._]min)?\.js", jl):
         add("Popper", [59], None, 100)
         
    if "vue." in jl or "vue.runtime" in jl:
        add("Vue.js", [66], None, 65)
    if "react" in jl or "react-dom" in jl:
        add("React", [59], None, 65)
    if "fontawesome" in jl or "font-awesome" in jl:
        add("Font Awesome", [17], None, 60)
    if "tailwind" in jl:
        add("Tailwind CSS", [66], None, 60)

    # ---- Extended heuristics for WordPress ecosystem & common technologies ----
    # Yoast SEO: HTML comment marker
    if "yoast seo" in low_html or "yoast seo plugin" in low_html:
        add("Yoast SEO", [54, 32], None, 90)
    # Open Graph: og: meta tags
    if re.search(r'property=["\']og:', low_html):
        add("Open Graph", [19], None, 80)
    # RSS: link rel alternate rss
    if re.search(r'type=["\']application/rss\+xml["\']', low_html):
        add("RSS", [19], None, 80)
    # MonsterInsights: script/comment pattern
    if "monsterinsights" in jl:
        add("MonsterInsights", [10], None, 80)
    # Google Site Kit
    if "google-site-kit" in jl or "sitekit" in jl:
        add("Site Kit", [10], None, 75)
    # Elementor Header & Footer Builder
    if "elementor-hf" in jl or "header-footer-elementor" in jl:
        add("Elementor Header & Footer Builder", [1], None, 75)
    # Hello Elementor theme
    if "hello-elementor" in jl or "hello elementor" in low_html:
        add("Hello Elementor Theme", [80], None, 75)
    # core-js
    if "core-js" in jl or "core.js" in jl:
        add("core-js", [59], None, 70)
    # Svelte
    if "svelte" in jl:
        add("Svelte", [12], None, 65)
    # Marked (markdown parser)
    if re.search(r"marked(?:[-._]min)?\.js", jl):
        add("Marked", [59], None, 70)
    # Twitter Emoji (Twemoji)
    if "twemoji" in jl:
        add("Twitter Emoji (Twemoji)", [17], None, 80)
    # UserWay accessibility widget
    if "userway" in jl:
        add("UserWay", [68], None, 80)
    # WhatsApp Business Chat widget
    if "whatsapp" in jl or "wa.me" in jl:
        add("WhatsApp Business Chat", [52], None, 65)
    # SuperPWA
    if "superpwa" in jl:
        add("SuperPWA", [59], None, 80)
    # PWA: manifest link
    if re.search(r'rel=["\']manifest["\']', low_html):
        add("PWA", [59], None, 60)
    # Priority Hints: fetchpriority attribute
    if "fetchpriority" in low_html:
        add("Priority Hints", [42], None, 70)
    # Progressive Web App (from manifest link)
    if re.search(r'rel=["\']manifest["\']', low_html):
        add("Progressive Web App", [59], None, 55)
    # Webpack: chunk/bundle patterns
    if re.search(r"webpack|__webpack_", jl):
        add("Webpack", [19], None, 60)
    # Module Federation
    if "remoteentry" in jl or "module-federation" in jl:
        add("Module Federation", [19], None, 60)

    return {
        "technologies": techs,
        "extras": {
            "headers": headers,
            "meta": meta_map,
            "scripts": script_srcs,
            "links": link_hrefs,
            "url": url_s,
        },
    }
