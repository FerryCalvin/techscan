import json, subprocess, threading, uuid, time, os, logging
from typing import Optional, Dict, Any

_proc: subprocess.Popen | None = None
_lock = threading.Lock()
_responses: Dict[str, Dict[str, Any]] = {}
_cond = threading.Condition(_lock)
_fail_window: list[float] = []  # timestamps of recent failures

def _watchdog_check() -> None:
    """Restart process if failures exceed threshold within window.
    Controlled by env:
      TECHSCAN_PERSIST_WATCHDOG=1
      TECHSCAN_PERSIST_FAIL_THRESHOLD (default 5)
      TECHSCAN_PERSIST_RESTART_WINDOW (seconds, default 180)
    """
    if os.environ.get('TECHSCAN_PERSIST_WATCHDOG','0') != '1':
        return
    try:
        threshold = int(os.environ.get('TECHSCAN_PERSIST_FAIL_THRESHOLD','5'))
        window = int(os.environ.get('TECHSCAN_PERSIST_RESTART_WINDOW','180'))
    except ValueError:
        threshold, window = 5, 180
    now = time.time()
    # prune
    global _fail_window
    _fail_window = [t for t in _fail_window if now - t <= window]
    if len(_fail_window) >= threshold:
        logging.getLogger('techscan.persist').warning('watchdog restarting persistent browser (failures=%d in %ds)', len(_fail_window), window)
        _restart_process()
        _fail_window.clear()

def _restart_process():
    global _proc
    try:
        if _proc and _proc.poll() is None:
            _proc.terminate()
            try:
                _proc.wait(timeout=5)
            except Exception:
                _proc.kill()
    except Exception:
        pass
    _proc = None
    _ensure_process()

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
        # Count as failure and maybe restart
        _fail_window.append(time.time())
        _watchdog_check()
        raise RuntimeError(f'failed writing to persistent process: {e}')
    # wait
    deadline = time.time() + float(os.environ.get('TECHSCAN_PERSIST_TIMEOUT','70'))
    with _cond:
        while _id not in _responses and time.time() < deadline:
            _cond.wait(timeout=1)
        resp = _responses.pop(_id, None)
    if not resp:
        _fail_window.append(time.time())
        _watchdog_check()
        raise TimeoutError('persistent scanner timeout waiting response')
    return resp

def scan(domain: str, full: bool = False) -> dict:
    url = domain
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    resp = _send({'cmd': 'scan', 'url': url, 'full': full})
    if not resp.get('ok'):
        _fail_window.append(time.time())
        _watchdog_check()
        raise RuntimeError(resp.get('error') or 'scan failed')
    return resp['result']

def ping() -> dict:
    return _send({'cmd': 'ping'})

def shutdown() -> None:
    try:
        _send({'cmd': 'shutdown'})
    except Exception:
        pass