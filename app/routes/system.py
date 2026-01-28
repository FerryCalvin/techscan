import os, time, pathlib
from flask import Blueprint, jsonify
from .. import scan_utils
from .. import persistent_client as _persist

system_bp = Blueprint('system', __name__)

_START_TIME = time.time()

def _get_commit_short() -> str:
    # Try to read git commit if repository available
    try:
        root = pathlib.Path(__file__).resolve().parent.parent.parent
        git_dir = root / '.git'
        if not git_dir.exists():
            return 'unknown'
        head_file = git_dir / 'HEAD'
        if not head_file.exists():
            return 'unknown'
        head_content = head_file.read_text().strip()
        if head_content.startswith('ref:'):
            ref_path = git_dir / head_content.split(' ',1)[1]
            if ref_path.exists():
                commit = ref_path.read_text().strip()[:7]
                return commit or 'unknown'
        return head_content[:7]
    except Exception:
        return 'unknown'

_COMMIT = _get_commit_short()
_VERSION = os.environ.get('TECHSCAN_VERSION', '0.3.0')

@system_bp.route('/health', methods=['GET'])
def health():
    # lightweight status; avoid heavy imports
    uptime = time.time() - _START_TIME
    return jsonify({'status': 'ok', 'uptime_seconds': round(uptime,2)})

@system_bp.route('/version', methods=['GET'])
def version():
    uptime = time.time() - _START_TIME
    features = {
        'synthetic_headers': os.environ.get('TECHSCAN_SYNTHETIC_HEADERS','1') == '1'
    }
    return jsonify({
        'version': _VERSION,
        'git_commit': _COMMIT,
        'uptime_seconds': round(uptime,2),
        'features': features
    })

@system_bp.route('/metrics', methods=['GET'])
def metrics():
    """Return internal metrics including cache stats, durations, phase aggregates."""
    base = scan_utils.get_stats()
    # Append phase aggregates and totals (non-disruptive to existing get_stats API consumers)
    with scan_utils._stats_lock:  # type: ignore
        phases = dict(scan_utils.STATS.get('phases', {}))  # type: ignore
        totals = dict(scan_utils.STATS.get('totals', {}))  # type: ignore
    base['phase_aggregates'] = phases
    base['overall_totals'] = totals
    # Persistent worker metrics (best-effort; only if enabled / started once)
    try:
        base['persistent_worker'] = _persist.get_metrics_snapshot()
    except Exception:
        base['persistent_worker'] = {'available': False}
    return jsonify(base)


@system_bp.route('/metrics/prometheus', methods=['GET'])
def metrics_prometheus():
    """Expose a tiny Prometheus-compatible metrics text endpoint.

    Currently exports only DB pool related gauges (if pool exists).
    This avoids colliding with the existing JSON `/metrics` endpoint used by
    the UI and other consumers.
    """
    from flask import Response
    try:
        from .. import db as _dbmod
        stats = _dbmod.pool_stats() or {}
    except Exception:
        stats = {'pool': None}
    lines = [
        '# HELP db_pool_in_use Number of active DB connections',
        '# TYPE db_pool_in_use gauge',
    ]
    # Defensive formatting: use 0 when values are missing
    in_use = stats.get('in_use') if isinstance(stats.get('in_use'), (int,float)) else 0
    avail = stats.get('available') if isinstance(stats.get('available'), (int,float)) else 0
    max_size = stats.get('max_size') if isinstance(stats.get('max_size'), (int,float)) else 0
    lines.append(f'db_pool_in_use {in_use}')
    lines.append('# HELP db_pool_available Number of available connections in pool')
    lines.append('# TYPE db_pool_available gauge')
    lines.append(f'db_pool_available {avail}')
    lines.append('# HELP db_pool_max_size Configured max pool size')
    lines.append('# TYPE db_pool_max_size gauge')
    lines.append(f'db_pool_max_size {max_size}')
    # Additional lightweight metrics for operational visibility
    try:
        total = (int(in_use) + int(avail)) if (in_use is not None and avail is not None) else 0
    except Exception:
        total = 0
    try:
        saturation = float(in_use) / float(max_size) if max_size else 0.0
    except Exception:
        saturation = 0.0
    import time as _time
    lines.append('# HELP db_pool_total_connections Total connections allocated by the pool')
    lines.append('# TYPE db_pool_total_connections gauge')
    lines.append(f'db_pool_total_connections {total}')
    lines.append('# HELP db_pool_saturation_ratio Ratio in_use / max_size (0..1)')
    lines.append('# TYPE db_pool_saturation_ratio gauge')
    lines.append(f'db_pool_saturation_ratio {saturation:.2f}')
    lines.append('# HELP db_pool_last_update_timestamp_seconds Epoch seconds when metrics were generated')
    lines.append('# TYPE db_pool_last_update_timestamp_seconds gauge')
    lines.append(f'db_pool_last_update_timestamp_seconds {_time.time()}')
    # Additional derived metrics: total connections, saturation ratio, last update timestamp
    try:
        total = (int(in_use) + int(avail)) if (in_use is not None and avail is not None) else 0
    except Exception:
        total = 0
    try:
        sat = (float(in_use) / float(max_size)) if (max_size and float(max_size) > 0) else 0.0
    except Exception:
        sat = 0.0
    import time as _time
    ts = _time.time()
    lines.append('# HELP db_pool_total_connections Total number of connections allocated by the pool')
    lines.append('# TYPE db_pool_total_connections gauge')
    lines.append(f'db_pool_total_connections {total}')
    lines.append('# HELP db_pool_saturation_ratio Fraction of pool in use (0..1)')
    lines.append('# TYPE db_pool_saturation_ratio gauge')
    lines.append(f'db_pool_saturation_ratio {sat:.2f}')
    lines.append('# HELP db_pool_last_update_timestamp_seconds Unix epoch timestamp when metrics produced')
    lines.append('# TYPE db_pool_last_update_timestamp_seconds gauge')
    lines.append(f'db_pool_last_update_timestamp_seconds {ts}')
    # Additional lightweight metrics: total connections, saturation ratio, last update timestamp
    try:
        total_conn = int(in_use + avail)
    except Exception:
        total_conn = 0
    try:
        saturation = float(in_use) / float(max_size) if max_size else 0.0
    except Exception:
        saturation = 0.0
    import time as _time
    last_ts = _time.time()
    lines.append('# HELP db_pool_total_connections Total number of connections allocated by the pool')
    lines.append('# TYPE db_pool_total_connections gauge')
    lines.append(f'db_pool_total_connections {total_conn}')
    lines.append('# HELP db_pool_saturation_ratio Ratio of in_use to max_size (0..1)')
    lines.append('# TYPE db_pool_saturation_ratio gauge')
    lines.append(f'db_pool_saturation_ratio {saturation:.2f}')
    lines.append('# HELP db_pool_last_update_timestamp_seconds Unix epoch seconds when metrics were emitted')
    lines.append('# TYPE db_pool_last_update_timestamp_seconds gauge')
    lines.append(f'db_pool_last_update_timestamp_seconds {last_ts}')
    # Additional convenience metrics: total connections, saturation ratio, last update timestamp
    try:
        total_conns = (int(in_use or 0) + int(avail or 0))
    except Exception:
        total_conns = 0
    try:
        sat = float(in_use) / float(max_size) if max_size else 0.0
    except Exception:
        sat = 0.0
    import time as _time
    lines.append('# HELP db_pool_total_connections Total number of connections currently allocated by the pool')
    lines.append('# TYPE db_pool_total_connections gauge')
    lines.append(f'db_pool_total_connections {total_conns}')
    lines.append('# HELP db_pool_saturation_ratio Fraction of pool currently in use (0..1)')
    lines.append('# TYPE db_pool_saturation_ratio gauge')
    lines.append(f'db_pool_saturation_ratio {sat:.2f}')
    lines.append('# HELP db_pool_last_update_timestamp_seconds Last update timestamp (epoch seconds)')
    lines.append('# TYPE db_pool_last_update_timestamp_seconds gauge')
    lines.append(f'db_pool_last_update_timestamp_seconds {_time.time()}')
    # Enrichment metrics (aggregate snapshot from scan_utils.STATS)
    try:
        # read a small snapshot under the same lock used by scan_utils
        with scan_utils._stats_lock:  # type: ignore
            enrich = dict(scan_utils.STATS.get('enrichment', {}))  # type: ignore
    except Exception:
        enrich = {'hints_total': 0, 'scans': 0, 'last_avg_conf': 0.0}
    try:
        hint_total = int(enrich.get('hints_total') or 0)
    except Exception:
        hint_total = 0
    try:
        enrich_scans = int(enrich.get('scans') or 0)
    except Exception:
        enrich_scans = 0
    try:
        last_avg = float(enrich.get('last_avg_conf') or 0.0)
    except Exception:
        last_avg = 0.0
    try:
        merge_total = int(enrich.get('merge_total') or 0)
    except Exception:
        merge_total = 0
    lines.extend([
        '# HELP techscan_enrichment_hints_total Cumulative number of enrichment hints detected',
        '# TYPE techscan_enrichment_hints_total counter',
        f'techscan_enrichment_hints_total {hint_total}',
        '# HELP techscan_enrichment_scan_count Number of scans that emitted enrichment hints',
        '# TYPE techscan_enrichment_scan_count counter',
        f'techscan_enrichment_scan_count {enrich_scans}',
        '# HELP techscan_enrichment_avg_confidence Last observed average confidence for enrichment hints',
        '# TYPE techscan_enrichment_avg_confidence gauge',
        f'techscan_enrichment_avg_confidence {last_avg}',
    ])
    # Emit last update timestamp (epoch seconds) for alerting and recency checks
    try:
        last_update = int(enrich.get('last_update') or 0)
    except Exception:
        last_update = 0
    lines.extend([
        '# HELP techscan_enrichment_last_update_seconds Epoch seconds when enrichment was last recorded',
        '# TYPE techscan_enrichment_last_update_seconds gauge',
        f'techscan_enrichment_last_update_seconds {last_update}',
    ])
    # expose merge counter: number of hints merged into final unified results
    lines.extend([
        '# HELP techscan_enrichment_merge_total Cumulative number of enrichment hints merged into final results',
        '# TYPE techscan_enrichment_merge_total counter',
        f'techscan_enrichment_merge_total {merge_total}',
    ])
    # Emit scan throughput metrics: total scans and scans per minute since process start
    try:
        with scan_utils._stats_lock:  # type: ignore
            totals = dict(scan_utils.STATS.get('totals', {}))
            start_time = float(scan_utils.STATS.get('start_time', 0.0))
        scans_total = int(totals.get('scan_count') or scan_utils.STATS.get('scans') or 0)
    except Exception:
        scans_total = 0
        start_time = time.time()
    try:
        uptime_minutes = max(1.0, (time.time() - start_time) / 60.0)
        scans_per_min = float(scans_total) / uptime_minutes
    except Exception:
        scans_per_min = 0.0
    lines.extend([
        '# HELP techscan_scans_total Cumulative number of scans performed by this process',
        '# TYPE techscan_scans_total counter',
        f'techscan_scans_total {scans_total}',
        '# HELP techscan_scans_per_minute Rolling average scans per minute since process start',
        '# TYPE techscan_scans_per_minute gauge',
        f'techscan_scans_per_minute {scans_per_min:.2f}',
    ])
    
    # Append metrics from prometheus_client registry (scan duration histogram, etc.)
    try:
        from .. import metrics as _metrics
        if _metrics.PROMETHEUS_AVAILABLE:
            prometheus_output = _metrics.get_metrics().decode('utf-8')
            lines.append('')
            lines.append('# === Prometheus Client Metrics ===')
            lines.append(prometheus_output)
    except Exception:
        pass  # prometheus_client not available or error
    
    # Timestamp optional
    try:
        body = '\n'.join(lines) + '\n'
        return Response(body, mimetype='text/plain')
    except Exception:
        return Response('# error\n', mimetype='text/plain')



# Compatibility JSON endpoint used by the UI
@system_bp.route('/api/system_health', methods=['GET'])
def api_system_health():
    # Provide a small JSON structure the frontend expects.
    try:
        uptime = round(time.time() - _START_TIME, 2)
    except Exception:
        uptime = 0
    # enrichment.merge_total if available
    try:
        with scan_utils._stats_lock:  # type: ignore
            enrich = dict(scan_utils.STATS.get('enrichment', {}))  # type: ignore
    except Exception:
        enrich = {}
    try:
        merge_total = int(enrich.get('merge_total') or 0)
    except Exception:
        merge_total = 0
    # Build a best-effort diagnostic snapshot. Keep checks lightweight and
    # non-failing so the endpoint remains usable even when components error.
    out = {
        'enrichment': {'merge_total': merge_total},
        'uptime_seconds': uptime
    }

    # DB diagnostics (best-effort)
    try:
        from .. import db as dbmod
        diag = dbmod.get_db_diagnostics()
        if diag.get('disabled'):
            out['db'] = 'disabled'
        elif diag.get('ok'):
            out['db'] = 'ok'
        else:
            # reachable but reports problems
            out['db'] = 'warn'
        # include lightweight diagnostic snapshot for UI or tooling
        out['db_diag'] = {
            'ok': diag.get('ok'),
            'latency_ms': diag.get('latency_ms'),
            'scans_count': diag.get('scans_count'),
            'domain_techs_count': diag.get('domain_techs_count'),
            'error': diag.get('error')
        }
    except Exception as e:
        out['db'] = 'unknown'
        out['db_diag'] = {'error': str(e)}

    # Redis (if configured) - reuse same defensive pattern as admin.redis_health
    try:
        url = os.environ.get('TECHSCAN_REDIS_URL')
        if not url:
            out['redis'] = 'disabled'
        else:
            try:
                from redis import from_url
                r = from_url(url, socket_connect_timeout=1)
                pong = r.ping()
                out['redis'] = 'ok' if pong else 'warn'
                out['redis_diag'] = {'ping': pong}
            except Exception as re:
                out['redis'] = 'warn'
                out['redis_diag'] = {'error': str(re)}
    except Exception as e:
        out['redis'] = 'unknown'
        out['redis_diag'] = {'error': str(e)}

    # Persistent queue / worker (node_scanner) metrics (best-effort)
    try:
        try:
            pc_metrics = _persist.get_metrics_snapshot()
        except Exception:
            pc_metrics = None
        if pc_metrics:
            # if metrics are present assume available
            out['queue'] = 'ok'
            out['queue_diag'] = pc_metrics
        else:
            out['queue'] = 'unknown'
            out['queue_diag'] = {'available': False}
    except Exception as e:
        out['queue'] = 'unknown'
        out['queue_diag'] = {'error': str(e)}

    return jsonify(out)
