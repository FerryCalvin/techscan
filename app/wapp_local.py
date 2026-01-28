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

    for scheme, Conn in schemes:
        if remaining() <= 0:
            break
        try:
            conn = Conn(target_host, timeout=remaining())
            conn.request("GET", target_path, headers={"User-Agent": "TechScan-PyLocal/1.0"})
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

        # Second pass: apply implies
        for name, spec in rules["techs"].items():
            if name in detected:
                for imp in spec.get("implies") or []:
                    if isinstance(imp, str) and imp not in detected and imp in rules["techs"]:
                        add(imp, rules["techs"][imp].get("cats", []), None, 25)
    else:
        # Lightweight fallback heuristics so detection provides hints without rule files
        joined = "\n".join(script_srcs + link_hrefs + [low_html])
        jl = joined.lower()
        if "jquery" in jl:
            add("jQuery", [], None, 80)
        if "bootstrap" in jl:
            add("Bootstrap", [], None, 70)
        if "vue." in jl or "vue.runtime" in jl:
            add("Vue.js", [], None, 65)
        if "react" in jl or "react-dom" in jl:
            add("React", [], None, 65)
        if "fontawesome" in jl or "font-awesome" in jl:
            add("Font Awesome", [], None, 60)
        if "tailwind" in jl:
            add("Tailwind CSS", [], None, 60)

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
