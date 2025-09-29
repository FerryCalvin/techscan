import os, logging
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def create_app():
    app = Flask(__name__)
    app.config['WAPPALYZER_PATH'] = os.environ.get('WAPPALYZER_PATH', r'd:\wappalyzer\wappalyzer3\wappalyzer-master')

    # Logging configuration
    level_name = os.environ.get('TECHSCAN_LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger(__name__).info('Logging initialized at level %s', level_name)

    # Rate limiting configuration
    default_rate = os.environ.get('TECHSCAN_RATE_LIMIT', '60 per minute')
    limiter = Limiter(get_remote_address, app=app, default_limits=[default_rate])

    # Expose limiter for blueprints to use specific limits
    app.extensions['limiter'] = limiter

    # register blueprints
    from .routes.scan import bp as scan_bp
    from .routes.ui import ui_bp
    from .routes.admin import admin_bp
    from .routes.system import system_bp
    # Ensure DB schema (Postgres) if configured
    try:
        from . import db as _db
        _db.ensure_schema()
    except Exception as db_ex:
        logging.getLogger(__name__).error('Failed ensuring DB schema: %s', db_ex)
    app.register_blueprint(scan_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(system_bp)

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
    return app
