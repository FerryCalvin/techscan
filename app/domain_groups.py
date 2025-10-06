import json, os, time, threading, logging
from typing import Dict, List, Tuple

_GROUPS_PATH = os.environ.get('TECHSCAN_DOMAIN_GROUPS_FILE', os.path.join(os.path.dirname(__file__), '..', 'data', 'domain_groups.json'))
_lock = threading.Lock()
_groups_cache: dict = {}
_groups_mtime: float | None = None
_logger = logging.getLogger('techscan.domain_groups')

DEFAULT_KEYS = ["faculty", "directorate", "work_unit", "bem_ukm"]

class DomainGroups:
    def __init__(self, groups: Dict[str, List[str]], version: int | None = None, updated_at: float | None = None):
        self.groups = groups
        self.version = version
        self.updated_at = updated_at

    def all_domains(self) -> List[str]:
        seen = set()
        for arr in self.groups.values():
            for d in arr:
                seen.add(d)
        return sorted(seen)

    def membership(self, domain: str) -> List[str]:
        out = []
        for k, arr in self.groups.items():
            if domain in arr:
                out.append(k)
        return out

_cached_obj: DomainGroups | None = None

def _ensure_defaults(data: dict) -> dict:
    groups = data.get('groups') or {}
    changed = False
    for k in DEFAULT_KEYS:
        if k not in groups:
            groups[k] = []
            changed = True
    if changed:
        data['groups'] = groups
    return data

def load(force: bool = False) -> DomainGroups:
    global _groups_cache, _groups_mtime, _cached_obj
    path = os.path.abspath(_GROUPS_PATH)
    try:
        st = os.stat(path)
        mtime = st.st_mtime
    except FileNotFoundError:
        # initialize empty structure
        data = {"version": 1, "updated_at": None, "groups": {k: [] for k in DEFAULT_KEYS}}
        return DomainGroups(data['groups'], data['version'], data['updated_at'])
    with _lock:
        if not force and _cached_obj is not None and _groups_mtime == mtime:
            return _cached_obj
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            _logger.warning('failed_load_domain_groups err=%s path=%s', e, path)
            data = {"version": 1, "updated_at": None, "groups": {k: [] for k in DEFAULT_KEYS}}
        data = _ensure_defaults(data)
        _groups_mtime = mtime
        _cached_obj = DomainGroups(data.get('groups') or {}, data.get('version'), data.get('updated_at'))
        return _cached_obj

def reload() -> DomainGroups:
    return load(force=True)


def group_domains(domain_meta: List[Tuple[str, float | None, str | None, int | None]], extras: dict | None = None):
    """Group domains according to groups file.
    Input: list tuples (domain, last_scan_ts, last_mode, tech_count)
    Returns: dict structure for /api/domains endpoint
    """
    dg = load()
    groups = dg.groups
    # Build reverse map for quick membership
    rev = {}
    for gk, arr in groups.items():
        for d in arr:
            rev.setdefault(d, []).append(gk)
    grouped = {k: [] for k in groups.keys()}
    ungrouped = []
    for domain, last_scan_ts, last_mode, tech_count in domain_meta:
        buckets = rev.get(domain)
        entry = {
            'domain': domain,
            'last_scan_ts': last_scan_ts,
            'last_mode': last_mode,
            'tech_count': tech_count or 0
        }
        if extras and domain in extras:
            try:
                entry.update(extras.get(domain) or {})
            except Exception:
                pass
        if not buckets:
            ungrouped.append(entry)
        else:
            for b in buckets:
                grouped[b].append(entry)
    # Sort entries per group by last_scan_ts desc (None last)
    def sort_key(e):
        ts = e.get('last_scan_ts')
        return (0, -ts) if ts else (1, 0)
    for arr in grouped.values():
        arr.sort(key=sort_key)
    ungrouped.sort(key=sort_key)
    # counts
    groups_out = []
    for k, arr in grouped.items():
        groups_out.append({
            'key': k,
            'label': k.replace('_', ' ').title(),
            'count': len(arr),
            'domains': arr
        })
    total_domains = len(domain_meta)
    scanned = sum(1 for _, ts, _, _ in domain_meta if ts)
    return {
        'generated_at': time.time(),
        'groups': groups_out,
        'ungrouped': ungrouped,
        'summary': {
            'total_domains': total_domains,
            'scanned': scanned,
            'unscanned': total_domains - scanned
        }
    }
