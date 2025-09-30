import json, subprocess, threading, uuid, time, os, logging
from typing import Optional, Dict, Any

_proc: subprocess.Popen | None = None
_lock = threading.Lock()
_responses: Dict[str, Dict[str, Any]] = {}
_cond = threading.Condition(_lock)

def _ensure_process() -> None:
    global _proc
    if _proc and _proc.poll() is None:
        return
    node_path = os.environ.get('TECHSCAN_NODE', 'node')
    server_js = os.path.join(os.path.dirname(__file__), '..', 'node_scanner', 'server.js')
    server_js = os.path.abspath(server_js)
    if not os.path.exists(server_js):
        raise FileNotFoundError('server.js not found for persistent mode')
    logging.getLogger('techscan.persist').info('starting persistent scanner daemon: %s %s', node_path, server_js)
    _proc = subprocess.Popen([node_path, server_js], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)  # line buffered
    threading.Thread(target=_reader_thread, name='techscan-persist-reader', daemon=True).start()

def _reader_thread():
    assert _proc is not None
    for line in _proc.stdout:  # type: ignore
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        _id = msg.get('id')
        if not _id:
            continue
        with _cond:
            _responses[_id] = msg
            _cond.notify_all()

def _send(message: dict) -> dict:
    _ensure_process()
    assert _proc is not None and _proc.stdin is not None
    _id = message.get('id') or str(uuid.uuid4())
    message['id'] = _id
    data = json.dumps(message, separators=(',', ':')) + '\n'
    try:
        _proc.stdin.write(data)
        _proc.stdin.flush()
    except Exception as e:
        raise RuntimeError(f'failed writing to persistent process: {e}')
    # wait
    deadline = time.time() + float(os.environ.get('TECHSCAN_PERSIST_TIMEOUT','70'))
    with _cond:
        while _id not in _responses and time.time() < deadline:
            _cond.wait(timeout=1)
        resp = _responses.pop(_id, None)
    if not resp:
        raise TimeoutError('persistent scanner timeout waiting response')
    return resp

def scan(domain: str, full: bool = False) -> dict:
    url = domain
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    resp = _send({'cmd': 'scan', 'url': url, 'full': full})
    if not resp.get('ok'):
        raise RuntimeError(resp.get('error') or 'scan failed')
    return resp['result']

def ping() -> dict:
    return _send({'cmd': 'ping'})

def shutdown() -> None:
    try:
        _send({'cmd': 'shutdown'})
    except Exception:
        pass