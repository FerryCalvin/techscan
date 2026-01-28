import json, os, time, threading, logging, tempfile
from typing import Dict, List

_GROUPS_PATH = os.environ.get(
    "TECHSCAN_DOMAIN_GROUPS_FILE", os.path.join(os.path.dirname(__file__), "..", "data", "domain_groups.json")
)
_lock = threading.RLock()
_groups_cache: dict = {}
_groups_mtime: float | None = None
_logger = logging.getLogger("techscan.domain_groups")
_last_write_error: dict | None = None

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
    groups = data.get("groups") or {}
    changed = False
    for k in DEFAULT_KEYS:
        if k not in groups:
            groups[k] = []
            changed = True
    if changed:
        data["groups"] = groups
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
        return DomainGroups(data["groups"], data["version"], data["updated_at"])
    with _lock:
        if not force and _cached_obj is not None and _groups_mtime == mtime:
            return _cached_obj
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            _logger.warning("failed_load_domain_groups err=%s path=%s", e, path)
            data = {"version": 1, "updated_at": None, "groups": {k: [] for k in DEFAULT_KEYS}}
        data = _ensure_defaults(data)
        _groups_mtime = mtime
        _cached_obj = DomainGroups(data.get("groups") or {}, data.get("version"), data.get("updated_at"))
        return _cached_obj


def reload() -> DomainGroups:
    return load(force=True)


# --- Write / mutate helpers ---


def _write_data(data: dict):
    """Atomically write domain groups data to disk (with fallback)."""
    global _last_write_error, _cached_obj, _groups_mtime
    path = os.path.abspath(_GROUPS_PATH)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp_fd = None
    tmp_path = None
    t0 = time.time()
    _logger.debug("domain_groups_write_start path=%s", path)
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="._dg", dir=directory)  # binary safe
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        # update mtime cache
        try:
            st = os.stat(path)
            _groups_mtime = st.st_mtime
        except Exception:
            pass
        _last_write_error = None
        _cached_obj = DomainGroups(data.get("groups", {}), data.get("version"), data.get("updated_at"))
        _logger.info(
            "domain_groups_write_success path=%s version=%s dur_ms=%d size=%s",
            path,
            data.get("version"),
            int((time.time() - t0) * 1000),
            os.path.exists(path) and os.path.getsize(path) or -1,
        )
    except Exception as e:
        _last_write_error = {"error": str(e), "path": path, "ts": time.time()}
        _logger.error("domain_groups_write_failed path=%s err=%s (attempting fallback direct write)", path, e)
        # Fallback direct write
        try:
            with open(path, "w", encoding="utf-8") as f2:
                json.dump(data, f2, indent=2, ensure_ascii=False)
            _last_write_error["fallback"] = "direct_ok"
            _logger.warning("domain_groups_fallback_direct_write_ok path=%s", path)
        except Exception as e2:
            _last_write_error["fallback"] = f"direct_failed:{e2}"
            _logger.exception("domain_groups_fallback_direct_write_failed path=%s err=%s", path, e2)
            raise
    finally:
        if tmp_path:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass


def _current_data() -> dict:
    obj = load()
    return {"version": obj.version or 1, "updated_at": obj.updated_at, "groups": obj.groups}


def _bump_version(data: dict):
    v = data.get("version") or 1
    data["version"] = v + 1
    data["updated_at"] = time.time()


def add_group(group: str) -> DomainGroups:
    group = (group or "").strip()
    if not group:
        raise ValueError("empty_group")
    with _lock:
        data = _current_data()
        groups = data.setdefault("groups", {})
        if group in groups:
            return _cached_obj or load()
        groups[group] = []
        _bump_version(data)
        _write_data(data)
        return _cached_obj or reload()


def delete_group(group: str) -> DomainGroups:
    group = (group or "").strip()
    if not group:
        raise ValueError("empty_group")
    with _lock:
        data = _current_data()
        groups = data.setdefault("groups", {})
        if group in groups:
            groups.pop(group)
            _bump_version(data)
            _write_data(data)
            return _cached_obj or reload()
        return _cached_obj or load()


def assign_domain(group: str, domain: str) -> DomainGroups:
    group = (group or "").strip()
    domain = (domain or "").strip().lower()
    if not group or not domain:
        raise ValueError("bad_params")
    with _lock:
        data = _current_data()
        groups = data.setdefault("groups", {})
        arr = groups.setdefault(group, [])
        if domain not in arr:
            arr.append(domain)
            arr.sort()
            _bump_version(data)
            _write_data(data)
            return _cached_obj or reload()
        return _cached_obj or load()


def remove_domain(group: str, domain: str) -> DomainGroups:
    group = (group or "").strip()
    domain = (domain or "").strip().lower()
    if not group or not domain:
        raise ValueError("bad_params")
    with _lock:
        data = _current_data()
        groups = data.setdefault("groups", {})
        arr = groups.get(group)
        if arr and domain in arr:
            arr.remove(domain)
            _bump_version(data)
            _write_data(data)
            return _cached_obj or reload()
        return _cached_obj or load()


def remove_domain_everywhere(domain: str) -> DomainGroups:
    domain = (domain or "").strip().lower()
    if not domain:
        raise ValueError("bad_params")
    with _lock:
        data = _current_data()
        groups = data.setdefault("groups", {})
        changed = False
        for arr in groups.values():
            if domain in arr:
                arr.remove(domain)
                changed = True
        if changed:
            _bump_version(data)
            _write_data(data)
            return _cached_obj or reload()
        return _cached_obj or load()

    def rename_group(old: str, new: str) -> DomainGroups:
        """Rename a group key while preserving domains. If new exists, merge domains.
        Raises ValueError on invalid params or if old not found.
        """
        old = (old or "").strip()
        new = (new or "").strip()
        if not old or not new:
            raise ValueError("bad_params")
        if old == new:
            return _cached_obj or load()
        with _lock:
            data = _current_data()
            groups = data.setdefault("groups", {})
            if old not in groups:
                raise ValueError("group_not_found")
            src_domains = groups.pop(old)
            dest = groups.setdefault(new, [])
            # merge unique
            merged = set(dest) | set(src_domains)
            groups[new] = sorted(merged)
            _bump_version(data)
            _write_data(data)
            return _cached_obj or reload()


def diagnostics() -> dict:
    path = os.path.abspath(_GROUPS_PATH)
    info = {"path": path}
    try:
        info["exists"] = os.path.exists(path)
        if info["exists"]:
            st = os.stat(path)
            info["size"] = st.st_size
            info["mtime"] = st.st_mtime
    except Exception as e:
        info["stat_error"] = str(e)
    info["cached_version"] = _cached_obj.version if _cached_obj else None
    info["last_write_error"] = _last_write_error
    try:
        info["dir_writable"] = os.access(os.path.dirname(path), os.W_OK)
        info["file_writable"] = os.access(path, os.W_OK) if info.get("exists") else True
    except Exception:
        pass
    info["lock_type"] = type(_lock).__name__
    return info


def group_domains(domain_meta: List[tuple], extras: dict | None = None):
    """Group domains according to groups file.
    Input tuples shaped like (domain, last_scan_ts, last_mode, tech_count[, payload_bytes])
    Returns structure for /api/domains endpoint.
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
    for meta in domain_meta:
        domain = meta[0]
        last_scan_ts = meta[1] if len(meta) > 1 else None
        last_mode = meta[2] if len(meta) > 2 else None
        tech_count = meta[3] if len(meta) > 3 else None
        payload_bytes = meta[4] if len(meta) > 4 else None
        buckets = rev.get(domain)
        entry = {
            "domain": domain,
            "last_scan_ts": last_scan_ts,
            "last_mode": last_mode,
            "tech_count": tech_count or 0,
            "payload_bytes": payload_bytes,
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
        ts = e.get("last_scan_ts")
        return (0, -ts) if ts else (1, 0)

    for arr in grouped.values():
        arr.sort(key=sort_key)
    ungrouped.sort(key=sort_key)
    # counts
    groups_out = []
    for k, arr in grouped.items():
        groups_out.append({"key": k, "label": k.replace("_", " ").title(), "count": len(arr), "domains": arr})
    total_domains = len(domain_meta)
    scanned = 0
    for meta in domain_meta:
        ts = meta[1] if len(meta) > 1 else None
        if ts:
            scanned += 1
    return {
        "generated_at": time.time(),
        "groups": groups_out,
        "ungrouped": ungrouped,
        "summary": {"total_domains": total_domains, "scanned": scanned, "unscanned": total_domains - scanned},
    }
