import os, time, json, pathlib, subprocess
from flask import Blueprint, jsonify, current_app

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
