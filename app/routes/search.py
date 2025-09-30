from flask import Blueprint, request, jsonify
import logging
from ..scan_utils import validate_domain
from .. import db as _db

search_bp = Blueprint('search', __name__)

@search_bp.route('/search', methods=['GET'])
def search_tech():
    tech = request.args.get('tech')
    category = request.args.get('category')
    version = request.args.get('version')
    limit = int(request.args.get('limit', 200))
    try:
        rows = _db.search_tech(tech=tech, category=category, version=version, limit=limit)
        return jsonify({'count': len(rows), 'results': rows})
    except Exception as e:
        logging.getLogger('techscan.search').error('search error tech=%s category=%s version=%s err=%s', tech, category, version, e)
        return jsonify({'error': 'search failed', 'details': str(e)}), 500

@search_bp.route('/history', methods=['GET'])
def history():
    domain = request.args.get('domain','').strip()
    if not domain:
        return jsonify({'error': 'missing domain'}), 400
    try:
        domain_norm = validate_domain(domain)
    except Exception:
        return jsonify({'error': 'invalid domain'}), 400
    limit = int(request.args.get('limit', 20))
    try:
        rows = _db.history(domain_norm, limit=limit)
        return jsonify({'domain': domain_norm, 'count': len(rows), 'history': rows})
    except Exception as e:
        logging.getLogger('techscan.search').error('history error domain=%s err=%s', domain_norm, e)
        return jsonify({'error': 'history failed'}), 500
