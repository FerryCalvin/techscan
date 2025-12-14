import os
import logging
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def create_app():
    # Ensure sensible defaults so the server will prefer persistent/full detection
    # across restarts unless explicitly overridden by the environment or .env file.
    os.environ.setdefault('TECHSCAN_PERSIST_BROWSER', '1')
    os.environ.setdefault('TECHSCAN_UNIFIED', '1')
    os.environ.setdefault('TECHSCAN_FORCE_FULL', '1')
    # Fail-fast defaults so unreachable hosts surface as explicit errors instead of slow 0-tech scans
    os.environ.setdefault('TECHSCAN_PREFLIGHT', '1')
    os.environ.setdefault('TECHSCAN_DNS_NEG_CACHE', '600')
    app = Flask(__name__)
    # Optional template auto-reload for development (to pick up index.html JS edits without restart)
    if os.environ.get('TECHSCAN_TEMPLATE_AUTO_RELOAD','0') == '1':
        app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['WAPPALYZER_PATH'] = os.environ.get('WAPPALYZER_PATH', r'd:\wappalyzer\wappalyzer3\wappalyzer-master')

    # Logging configuration
    level_name = os.environ.get('TECHSCAN_LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    # Optional rotating file handler for persistent logs (useful in production)
    log_file = os.environ.get('TECHSCAN_LOG_FILE')
    if log_file:
        try:
            from logging.handlers import RotatingFileHandler
            max_bytes = int(os.environ.get('TECHSCAN_LOG_MAX_BYTES', str(5 * 1024 * 1024)))
            backup = int(os.environ.get('TECHSCAN_LOG_BACKUP_COUNT', '5'))
            fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup)
            fh.setLevel(level)
            fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
            logging.getLogger().addHandler(fh)
            logging.getLogger(__name__).info(
                'RotatingFileHandler attached path=%s max_bytes=%d backups=%d',
                log_file, max_bytes, backup)
        except Exception:
            logging.getLogger(__name__).warning('failed attaching RotatingFileHandler for %s', log_file)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger(__name__).info('Logging initialized at level %s', level_name)
    if app.config.get('TEMPLATES_AUTO_RELOAD'):
        logging.getLogger(__name__).info('Template auto reload ENABLED')

    # Rate limiting configuration
    default_rate = os.environ.get('TECHSCAN_RATE_LIMIT', '60 per minute')
    # Use Redis storage for limiter when provided, otherwise fall back to in-memory storage
    redis_url = os.environ.get('TECHSCAN_REDIS_URL')
    storage_uri = redis_url if redis_url else 'memory://'
    try:
        limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[default_rate], storage_uri=storage_uri)
    except Exception:
        # Defensive fallback if storage driver unavailable -> memory
        limiter = Limiter(get_remote_address, app=app, default_limits=[default_rate])

    # Expose limiter for blueprints to use specific limits
    app.extensions['limiter'] = limiter

    # register blueprints
    from .routes.scan import bp as scan_bp
    from .routes.ui import ui_bp
    from .routes.admin import admin_bp
    from .routes.system import system_bp
    from .routes.search import search_bp
    # tech API blueprint (optional) - import safely
    try:
        from .routes.tech import bp as tech_bp
    except Exception:
        tech_bp = None
    # Ensure DB schema unless disabled
    if os.environ.get('TECHSCAN_DISABLE_DB','0') != '1':
        try:
            from . import db as _db
            # Log masked DB URL for diagnostics
            try:
                from urllib.parse import urlparse
                u = urlparse(_db.DB_URL)
                masked = f"{u.scheme}://{u.hostname}:{u.port or ''}{u.path}".rstrip(':')
                logging.getLogger(__name__).info('DB connecting masked_url=%s', masked)
            except Exception:
                pass
            _db.ensure_schema()
            # Quick test select to confirm live connection
            try:
                with _db.get_conn() as conn:  # type: ignore
                    with conn.cursor() as cur:
                        cur.execute('SELECT 1')
                        cur.fetchone()
                        logging.getLogger(__name__).info('DB connectivity check OK')
            except Exception as ce:
                logging.getLogger(__name__).error('DB connectivity check FAILED err=%s', ce)
        except Exception as db_ex:
            logging.getLogger(__name__).error('Failed ensuring DB schema: %s', db_ex)
    else:
        logging.getLogger(__name__).info('DB schema initialization skipped (TECHSCAN_DISABLE_DB=1)')
    app.register_blueprint(scan_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(search_bp)
    # register tech blueprint only if import succeeded
    if tech_bp:
        # Avoid registering the same blueprint object multiple times when
        # create_app() is called more than once (tests call create_app repeatedly).
        try:
            bp_name = getattr(tech_bp, 'name', None) or 'tech'
            existing = app.blueprints.get(bp_name)
            # Only register if no blueprint with the same name exists or it's a different object
            if existing is None or existing is not tech_bp:
                app.register_blueprint(tech_bp)
            else:
                logging.getLogger(__name__).debug('Tech blueprint already registered, skipping')
        except ValueError as ve:
            # Defensive: if registration still fails for any reason, log and continue
            logging.getLogger(__name__).warning('Tech blueprint registration skipped due to error: %s', ve)

    # If persistent browser mode requested, attempt to ensure the persistent
    # Node scanner daemon is started at application startup. This avoids a
    # situation where the first scans after a restart fall back to lighter
    # engines because the persistent process wasn't launched yet.
    try:
        # By default, attempt to ensure the persistent Node scanner daemon is running at
        # application startup. This prevents the first scans after a restart from
        # falling back to lightweight local detectors when the daemon hasn't been
        # launched yet. Set TECHSCAN_DISABLE_PERSIST_AUTOSTART=1 to opt-out.
        if os.environ.get('TECHSCAN_DISABLE_PERSIST_AUTOSTART', '0') != '1':
            try:
                from . import persistent_client as _pc
                try:
                    _pc._ensure_process()
                    logging.getLogger(__name__).info('Persistent scanner daemon ensured at startup')
                except Exception as pc_err:
                    logging.getLogger(__name__).warning(
                        'Failed to start persistent scanner daemon at startup: %s', pc_err)
            except Exception as import_err:
                logging.getLogger(__name__).warning(
                    'Failed importing persistent_client to start daemon: %s', import_err)
        else:
            logging.getLogger(__name__).info(
                'Persistent daemon autostart disabled via TECHSCAN_DISABLE_PERSIST_AUTOSTART')
    except Exception:
        # Defensive: never fail app startup because persistent daemon couldn't be ensured
        logging.getLogger(__name__).debug('Persistent startup block encountered an unexpected error')

    # Optionally start DB pool monitor (lightweight background thread) for observability
    try:
        # Import lazily to avoid importing DB layer when DB disabled in some test contexts
        from . import db as _db
        if os.environ.get('TECHSCAN_DB_POOL_MONITOR', '0') == '1':
            try:
                _db.start_pool_monitor()
                logging.getLogger(__name__).info('DB pool monitor started (TECHSCAN_DB_POOL_MONITOR=1)')
            except Exception as pm_err:
                logging.getLogger(__name__).warning('Failed to start DB pool monitor: %s', pm_err)
    except Exception:
        # Non-fatal: if db import/monitor cannot be started, continue
        logging.getLogger(__name__).debug('DB monitor startup skipped or failed')

    # Optionally start weekly rescan background thread (opt-in)
    try:
        from . import periodic
        periodic.start_weekly_rescan(app)
    except Exception:
        logging.getLogger(__name__).debug('weekly rescan startup skipped or failed')

    # Stats page auto-refresh configuration (default: manual/off)
    # Set TECHSCAN_STATS_AUTO_REFRESH=1 to enable auto-refresh with 5 minute interval
    app.config['STATS_AUTO_REFRESH'] = os.environ.get('TECHSCAN_STATS_AUTO_REFRESH', '0') == '1'
    refresh_interval = os.environ.get('TECHSCAN_STATS_AUTO_REFRESH_INTERVAL_MS', '300000')
    app.config['STATS_AUTO_REFRESH_INTERVAL_MS'] = int(refresh_interval)
    
    # Version / commit (surface in config for other components if needed)
    app.config['TECHSCAN_VERSION'] = os.environ.get('TECHSCAN_VERSION', '0.3.0')
    # Attempt to read short commit for logging (best-effort)
    try:
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        head = root / '.git' / 'HEAD'
        short = 'unknown'
        if head.exists():
            content = head.read_text().strip()
            if content.startswith('ref:'):
                ref = content.split(' ',1)[1]
                ref_file = root / '.git' / ref
                if ref_file.exists():
                    short = ref_file.read_text().strip()[:7] or 'unknown'
            else:
                short = content[:7]
        app.config['TECHSCAN_COMMIT'] = short
    except Exception:
        app.config['TECHSCAN_COMMIT'] = 'unknown'

    # --- Diagnostic: enumerate routes & ensure at least one public route listing endpoint ---
    try:
        rules = list(app.url_map.iter_rules())
        rule_paths = sorted({r.rule for r in rules})
        logging.getLogger(__name__).info('Route map initialized count=%d sample=%s', len(rule_paths), rule_paths[:15])
        existing_paths = set(rule_paths)
        # Always provide /identify for runtime process verification
        from flask import jsonify
        if '/identify' not in existing_paths:
            @app.route('/identify')  # type: ignore
            def _identify():  # pragma: no cover - diagnostic only
                import os as _os
                try:
                    rc = sorted({r.rule for r in app.url_map.iter_rules()})
                except Exception:
                    rc = []
                return jsonify({
                    'status': 'ok',
                    'pid': _os.getpid(),
                    'version': app.config.get('TECHSCAN_VERSION'),
                    'commit': app.config.get('TECHSCAN_COMMIT'),
                    'route_count': len(rc),
                    'has_websites': '/websites' in rc,
                    'has__routes': '/_routes' in rc
                })
        # If blueprint /_routes somehow missing (e.g. stale code deployed), add a fallback /routes
        if '/_routes' not in existing_paths and '/routes' not in existing_paths:
            @app.route('/routes')  # type: ignore
            def _fallback_routes():  # pragma: no cover - diagnostic only
                try:
                    out = []
                    for rule in app.url_map.iter_rules():
                        methods = sorted(m for m in rule.methods if m not in ('HEAD','OPTIONS'))
                        out.append({'rule': str(rule), 'endpoint': rule.endpoint, 'methods': methods})
                    out.sort(key=lambda x: x['rule'])
                    return jsonify({'status':'ok','fallback': True,'count': len(out),'routes': out})
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            logging.getLogger(__name__).warning(
                'Primary /_routes diagnostic endpoint absent; fallback /routes registered.')
        # Prometheus-friendly metrics endpoint (lightweight)
        from flask import Response
        @app.route('/metrics/prometheus')  # type: ignore
        def _metrics_prometheus():  # pragma: no cover - simple text output
            try:
                # Attempt to import DB module lazily; pool_stats is defensive
                from . import db as _db
                st = _db.pool_stats() or {}
                max_size = st.get('max_size') or 0
                available = st.get('available') or 0
                in_use = st.get('in_use') if st.get('in_use') is not None else (max_size - available if max_size else 0)
                num_connections = st.get('num_connections') or 0
            except Exception:
                max_size = available = in_use = num_connections = 0
            lines = [
                '# HELP db_pool_in_use Number of active DB connections',
                '# TYPE db_pool_in_use gauge',
                f'db_pool_in_use {int(in_use)}',
                '# HELP db_pool_available Number of available connections in the pool',
                '# TYPE db_pool_available gauge',
                f'db_pool_available {int(available)}',
                '# HELP db_pool_max_size Configured max pool size',
                '# TYPE db_pool_max_size gauge',
                f'db_pool_max_size {int(max_size)}',
                '# HELP db_pool_num_connections Number of allocated connections',
                '# TYPE db_pool_num_connections gauge',
                f'db_pool_num_connections {int(num_connections)}',
            ]
            return Response('\n'.join(lines) + '\n', mimetype='text/plain')

        # Note: Redis health endpoint is provided via admin blueprint (`/admin/redis_health`).
        # To avoid duplicate endpoint registration, do not register an app-level route here.
    except Exception as diag_ex:
        logging.getLogger(__name__).warning('Failed enumerating routes at startup err=%s', diag_ex)
    return app
