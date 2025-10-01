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
