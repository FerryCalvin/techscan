import json, pathlib, os, re
from functools import lru_cache
from typing import Dict, Any, List

SEMVER_RE = re.compile(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$')

@lru_cache(maxsize=1)
def load_latest_versions(path: str | None = None) -> Dict[str,str]:
    if path is None:
        path = os.environ.get('TECHSCAN_LATEST_VERSIONS_FILE') or str(pathlib.Path(__file__).resolve().parent.parent / 'data' / 'latest_versions.json')
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
        return {str(k): str(v) for k,v in data.items() if isinstance(k,str)}
    except Exception:
        return {}

def _semver_tuple(v: str) -> tuple:
    m = SEMVER_RE.match(v.strip())
    if not m:
        return ()
    parts = [int(x) if x is not None else 0 for x in m.groups()]
    # Ensure length 3
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)

def compare_versions(found: str, latest: str) -> int:
    """Return -1 if found < latest, 0 if equal, 1 if newer/greater or incomparable.
    Non-semver or partial mismatch returns 1 (treat as not-outdated) to avoid false flagging.
    """
    if not found or not latest:
        return 1
    ft = _semver_tuple(found)
    lt = _semver_tuple(latest)
    if not ft or not lt:
        return 1
    if ft < lt:
        return -1
    if ft == lt:
        return 0
    return 1


def _prefer_newer_version(current: str | None, candidate: str | None) -> str | None:
    """Pick the newer-looking semantic version between current and candidate.

    Falls back to current when comparison fails so we avoid accidental downgrades.
    """
    if not candidate:
        return current
    if not current:
        return candidate
    cur = _semver_tuple(current)
    cand = _semver_tuple(candidate)
    if cand and cur:
        return candidate if cand > cur else current
    try:
        # prefer the one with more segments when we cannot parse both cleanly
        cur_parts = current.split('.')
        cand_parts = candidate.split('.')
        return candidate if len(cand_parts) > len(cur_parts) else current
    except Exception:
        return candidate

def diff_severity(found: str, latest: str) -> str | None:
    """Classify how far behind 'found' is vs 'latest'.
    Returns one of: 'major','minor','patch' or None if not outdated / incomparable.
    Logic:
      - If different major component → major
      - Else if different minor → minor
      - Else if different patch → patch
    """
    ft = _semver_tuple(found)
    lt = _semver_tuple(latest)
    if not ft or not lt:
        return None
    if ft >= lt:
        return None
    if ft[0] != lt[0]:
        return 'major'
    if ft[1] != lt[1]:
        return 'minor'
    if ft[2] != lt[2]:
        return 'patch'
    return None

def audit_versions(scan: Dict[str, Any], latest_map: Dict[str,str] | None = None) -> Dict[str, Any]:
    if latest_map is None:
        latest_map = load_latest_versions()
    if not latest_map:
        return scan
    # Ensure version evidence has been applied so we audit the highest confident version
    try:
        if os.environ.get('TECHSCAN_VERSION_EVIDENCE','1') == '1':
            apply_version_evidence(scan)
    except Exception:
        pass
    techs: List[Dict[str, Any]] = scan.get('technologies', [])
    # Early exit optimization: if no tech has version string, skip
    if not any(t.get('version') for t in techs):
        return scan
    outdated: List[Dict[str, Any]] = []
    annotated = False
    major_c = minor_c = patch_c = 0
    for t in techs:
        name = t.get('name')
        ver = t.get('version')
        if not name or not ver:
            continue
        latest = latest_map.get(name)
        if not latest or latest.lower() in ('n/a','unknown'):
            continue
        cmp = compare_versions(ver, latest)
        if cmp == -1:
            sev = diff_severity(ver, latest)
            t.setdefault('audit', {})['latest'] = latest
            t['audit']['status'] = 'outdated'
            if sev:
                t['audit']['difference'] = sev
                if sev == 'major':
                    major_c += 1
                elif sev == 'minor':
                    minor_c += 1
                elif sev == 'patch':
                    patch_c += 1
            outdated.append({'name': name, 'version': ver, 'latest': latest, 'difference': sev})
            annotated = True
        elif cmp == 0:
            t.setdefault('audit', {})['latest'] = latest
            t['audit']['status'] = 'latest'
            annotated = True
    if annotated:
        meta = scan.setdefault('audit', {})
        if outdated:
            meta['outdated_count'] = len(outdated)
            meta['outdated'] = outdated
            meta['outdated_major'] = major_c
            meta['outdated_minor'] = minor_c
            meta['outdated_patch'] = patch_c
        meta['version_dataset'] = 'latest_versions.json'
    return scan

# ---------------- Version Evidence Extraction (static) -----------------

# Simple normalization: keep digits, dots and letters separators, trim
_SAFE_VER_RE = re.compile(r'[^0-9A-Za-z\.-]')

def normalize_version_str(v: str) -> str | None:
    if not v:
        return None
    v2 = _SAFE_VER_RE.sub('', v.strip())
    # reject obviously bogus like '1' or '1.0.0' for WordPress handled elsewhere; generic filter minimal
    if not any(ch.isdigit() for ch in v2):
        return None
    # collapse leading/trailing dots
    v2 = v2.strip('.')
    return v2 or None

def extract_versions_from_meta(meta: Dict[str, str]) -> List[Dict[str, Any]]:
    evidences: List[Dict[str, Any]] = []
    if not meta:
        return evidences
    # Common generators: WordPress, Joomla, Drupal, Next.js, Hugo, Gatsby, Laravel
    gen = meta.get('generator') or meta.get('x-generator') or meta.get('powered-by')
    if gen:
        g = gen.strip()
        # Try capture last token with digits
        m = re.search(r'(\d+[^\s]*)', g)
        if m:
            nv = normalize_version_str(m.group(1))
            if nv:
                evidences.append({'tech_hint': g.lower(), 'source': 'meta.generator', 'raw': gen, 'normalized': nv, 'weight': 0.55})
    return evidences

_ASSET_VER_RE = re.compile(r'[\/?&](?:v|ver|version)=([0-9][0-9A-Za-z\.-]{0,30})', re.I)
_ASSET_PATH_VER_RE = re.compile(r'/([0-9]+\.[0-9][0-9A-Za-z\.-]{0,20})[\./-]')

def extract_versions_from_assets(urls: List[str]) -> List[Dict[str, Any]]:
    evidences: List[Dict[str, Any]] = []
    if not urls:
        return evidences
    # Look for ?ver=, ?v=, /1.2.3/
    for u in urls:
        if not isinstance(u, str) or len(u) > 600:
            continue
        m = _ASSET_VER_RE.search(u)
        if m:
            nv = normalize_version_str(m.group(1))
            if nv:
                evidences.append({'source': 'asset.query', 'raw': u, 'normalized': nv, 'weight': 0.35})
                continue
        m2 = _ASSET_PATH_VER_RE.search(u)
        if m2:
            nv = normalize_version_str(m2.group(1))
            if nv:
                evidences.append({'source': 'asset.path', 'raw': u, 'normalized': nv, 'weight': 0.25})
    return evidences

def combine_confidences(weights: List[float]) -> float:
    # 1 - Π(1-w)
    if not weights:
        return 0.0
    p = 1.0
    for w in weights:
        try:
            w2 = max(0.0, min(1.0, float(w)))
        except Exception:
            w2 = 0.0
        p *= (1.0 - w2)
    return round(1.0 - p, 4)

def apply_version_evidence(result: Dict[str, Any]) -> None:
    """Augment technologies with version_candidates and set version using simple voting.
    - Consumes extras.meta/scripts/links if present in result['raw'] or result itself.
    - Does not override an existing strong version unless new confidence is higher.
    """
    try:
        techs = result.get('technologies') or []
        if not techs:
            return
        # Gather extras
        extras = None
        raw = result.get('raw') or {}
        if isinstance(raw, dict):
            extras = raw.get('extras') or raw.get('data', {}).get('extras')
        if not extras and isinstance(result, dict):
            extras = result.get('extras')
        meta_raw = (extras or {}).get('meta') or {}
        if isinstance(meta_raw, list):
            meta_raw = meta_raw[0] if meta_raw and isinstance(meta_raw[0], dict) else {}
        meta = meta_raw if isinstance(meta_raw, dict) else {}
        scripts = (extras or {}).get('scripts') or []
        links = (extras or {}).get('links') or []
        evid_meta = extract_versions_from_meta(meta)
        evid_assets = extract_versions_from_assets([*scripts, *links])
        all_evid = evid_meta + evid_assets
        if not all_evid:
            return
        # Map evidence to technologies by loose hint
        for t in techs:
            name = (t.get('name') or '').lower()
            candidates: List[Dict[str, Any]] = t.setdefault('version_candidates', [])
            # Select evidences that likely belong to this tech
            rel = []
            for ev in all_evid:
                hint = (ev.get('tech_hint') or '')
                if not hint:
                    # Try map by common library asset names
                    raw = ev.get('raw') or ''
                    low = raw.lower()
                    if ('jquery' in low and 'jquery' in name) or \
                       ('react' in low and 'react' in name) or \
                       ('vue' in low and ('vue' in name or 'nuxt' in name)) or \
                       ('angular' in low and 'angular' in name) or \
                       ('wp-' in low and 'wordpress' in name):
                        rel.append(ev)
                else:
                    if name and name.split()[0] in hint:
                        rel.append(ev)
            # Add normalized deduped candidates
            seen = set((c.get('normalized'), c.get('source')) for c in candidates)
            for ev in rel:
                key = (ev.get('normalized'), ev.get('source'))
                if not ev.get('normalized') or key in seen:
                    continue
                candidates.append(ev)
                seen.add(key)
            if not candidates:
                continue
            # Pick winner by highest weight; compute confidence aggregate
            best = max(candidates, key=lambda c: c.get('weight', 0))
            conf = combine_confidences([c.get('weight', 0) for c in candidates])
            best_version = best.get('normalized')
            prev_conf = float(t.get('version_confidence') or 0.0)
            chosen_version = _prefer_newer_version(t.get('version'), best_version)
            if not t.get('version') or chosen_version != t.get('version'):
                t['version'] = chosen_version
                t['version_confidence'] = max(prev_conf, conf)
            elif conf > prev_conf:
                # keep current version but carry the stronger confidence signal
                t['version_confidence'] = conf
    except Exception:
        # best effort only
        return
