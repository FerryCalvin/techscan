from flask import Blueprint, request, jsonify, current_app
import os, logging
from ..scan_utils import flush_cache, load_heuristic_patterns, get_stats
import subprocess, pathlib, shlex

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

@admin_bp.route('/update_tech', methods=['POST'])
def update_tech():
    """Update technology definition data (Wappalyzer) without restarting.
    Strategy:
      1. If WAPPALYZER_PATH is a git repo -> git pull --ff-only
      2. Else if contains package.json -> npm update wappalyzer (or install if missing)
      3. Clear cached categories loader so new definitions picked up on next scan.
    Body (optional): {"force": true, "npm_cmd": "pnpm"}
    Returns JSON status + method + stdout/stderr snippet.
    """
    wpath = current_app.config.get('WAPPALYZER_PATH')
    if not wpath:
        return jsonify({'error': 'WAPPALYZER_PATH not configured'}), 400
    p = pathlib.Path(wpath)
    if not p.exists():
        return jsonify({'error': f'path not found: {wpath}'}), 400
    data = request.get_json(silent=True) or {}
    force = bool(data.get('force'))
    npm_cmd = data.get('npm_cmd') or os.environ.get('TECHSCAN_NPM_CMD') or 'npm'
    method = None
    stdout = ''
    stderr = ''
    try:
        if (p/'.git').exists():
            # Git repository update
            method = 'git-pull'
            cmd = ['git', '-C', str(p), 'pull', '--ff-only']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stdout, stderr = proc.stdout, proc.stderr
            if proc.returncode != 0:
                return jsonify({'error': 'git pull failed', 'method': method, 'stderr': stderr[-400:]}), 500
        else:
            pkg_json = p / 'package.json'
            if not pkg_json.exists():
                return jsonify({'error': 'No .git or package.json at WAPPALYZER_PATH; cannot auto-update.'}), 400
            # NPM update/install
            method = 'npm-update'
            # Force can trigger install of latest explicitly
            if force:
                cmd = [npm_cmd, 'install', 'wappalyzer@latest']
            else:
                cmd = [npm_cmd, 'update', 'wappalyzer']
            proc = subprocess.run(cmd, cwd=str(p), capture_output=True, text=True, timeout=240)
            stdout, stderr = proc.stdout, proc.stderr
            if proc.returncode != 0:
                return jsonify({'error': 'npm update failed', 'method': method, 'stderr': stderr[-400:]}), 500
        # Clear cached categories so new definitions used next scan
        try:
            from ..scan_utils import load_categories
            load_categories.cache_clear()  # type: ignore[attr-defined]
        except Exception as ce:
            logging.getLogger('techscan.admin').warning('failed clearing categories cache err=%s', ce)
        snippet_out = (stdout or '')[-400:]
        snippet_err = (stderr or '')[-400:]
        logging.getLogger('techscan.admin').info('update_tech success method=%s wpath=%s', method, wpath)
        return jsonify({'status': 'ok', 'method': method, 'stdout': snippet_out, 'stderr': snippet_err})
    except subprocess.TimeoutExpired:
        return jsonify({'error': f'{method or "update"} command timeout'}), 504
    except FileNotFoundError as nf:
        return jsonify({'error': f'command not found: {nf}'}), 500
    except Exception as e:
        logging.getLogger('techscan.admin').error('update_tech error method=%s err=%s', method, e)
        return jsonify({'error': str(e), 'method': method}), 500

@admin_bp.route('/runtime/state', methods=['GET'])
def runtime_state():
    """Return current runtime feature flags that can be toggled without restart.
    Flags surfaced:
      persist_browser: whether persistent Puppeteer daemon usage is enabled (TECHSCAN_PERSIST_BROWSER)
      tiered: whether tiered heuristic pre-scan stage is enabled (TECHSCAN_TIERED)
    """
    persist = os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1'
    tiered = os.environ.get('TECHSCAN_TIERED','0') == '1'
    return jsonify({'status': 'ok', 'flags': {
        'persist_browser': persist,
        'tiered': tiered
    }})

@admin_bp.route('/runtime/update', methods=['POST'])
def runtime_update():
    """Update runtime feature flags (no process restart required).
    Body JSON (all optional – only provided keys are applied):
      {
        "persist_browser": true|false,
        "tiered": true|false
      }
    Returns previous and new effective values.
    """
    data = request.get_json(silent=True) or {}
    applied = {}
    previous = {
        'persist_browser': os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1',
        'tiered': os.environ.get('TECHSCAN_TIERED','0') == '1'
    }
    # persist_browser toggle
    if 'persist_browser' in data:
        val = bool(data['persist_browser'])
        os.environ['TECHSCAN_PERSIST_BROWSER'] = '1' if val else '0'
        applied['persist_browser'] = val
    # tiered toggle (future heuristic stage)
    if 'tiered' in data:
        val = bool(data['tiered'])
        os.environ['TECHSCAN_TIERED'] = '1' if val else '0'
        applied['tiered'] = val
    new_state = {
        'persist_browser': os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1',
        'tiered': os.environ.get('TECHSCAN_TIERED','0') == '1'
    }
    logging.getLogger('techscan.admin').info('runtime flags update previous=%s new=%s applied_keys=%s', previous, new_state, list(applied.keys()))
    return jsonify({'status': 'ok', 'previous': previous, 'new': new_state, 'changed': applied})
