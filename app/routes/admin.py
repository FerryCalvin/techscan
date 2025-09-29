from flask import Blueprint, request, jsonify, current_app
import os, logging
from ..scan_utils import flush_cache, load_heuristic_patterns, get_stats

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def _check_auth():
    token_required = os.environ.get('TECHSCAN_ADMIN_TOKEN')
    if not token_required:  # open if not set
        return True
    provided = request.headers.get('X-Admin-Token')
    return provided == token_required

@admin_bp.before_request
def admin_auth():
    if not _check_auth():
        return jsonify({'error': 'unauthorized'}), 401

@admin_bp.route('/cache/flush', methods=['POST'])
def cache_flush():
    data = request.get_json(silent=True) or {}
    domains = data.get('domains') if isinstance(data.get('domains'), list) else None
    res = flush_cache(domains)
    logging.getLogger('techscan.admin').info('cache flush domains=%s removed=%s remaining=%s',
                                            'subset' if domains else 'all', res['removed'], res['remaining'])
    return jsonify({'status': 'ok', **res})

@admin_bp.route('/heuristics/reload', methods=['POST'])
def heuristics_reload():
    load_heuristic_patterns()  # will read default path or env
    return jsonify({'status': 'ok', 'message': 'heuristics reloaded'})

@admin_bp.route('/stats', methods=['GET'])
def stats_view():
    return jsonify({'status': 'ok', 'stats': get_stats()})
