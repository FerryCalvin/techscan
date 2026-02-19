import json, threading, uuid, time, os, logging
from typing import Dict, Any
from . import safe_subprocess as sproc

_proc: sproc.PopenType | None = None
_lock = threading.Lock()
_responses: Dict[str, Dict[str, Any]] = {}
_cond = threading.Condition(_lock)
_fail_window: list[float] = []  # timestamps of recent failures

# Metrics (local to persistent mode) - aggregated for /metrics exposure
_metrics = {
    "requests": 0,
    "failures": 0,
    "timeouts": 0,
    "restarts": 0,
    "last_start_ts": 0.0,
    "latency_ms_total": 0,
    "latency_ms_count": 0,
}

# Concurrency limiter: bound number of in-flight requests to daemon
_sem = threading.Semaphore(int(os.environ.get("TECHSCAN_NODE_CONCURRENCY", "3")))


def _watchdog_check() -> None:
    """Restart process if failures exceed threshold within window.
    Controlled by env:
      TECHSCAN_PERSIST_WATCHDOG=1
      TECHSCAN_PERSIST_FAIL_THRESHOLD (default 5)
      TECHSCAN_PERSIST_RESTART_WINDOW (seconds, default 180)
    """
    if os.environ.get("TECHSCAN_PERSIST_WATCHDOG", "0") != "1":
        return
    try:
        threshold = int(os.environ.get("TECHSCAN_PERSIST_FAIL_THRESHOLD", "5"))
        window = int(os.environ.get("TECHSCAN_PERSIST_RESTART_WINDOW", "180"))
    except ValueError:
        threshold, window = 5, 180
    now = time.time()
    # prune
    global _fail_window
    _fail_window = [t for t in _fail_window if now - t <= window]
    if len(_fail_window) >= threshold:
        logging.getLogger("techscan.persist").warning(
            "watchdog restarting persistent browser (failures=%d in %ds)", len(_fail_window), window
        )
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
    with _lock:
        _metrics["restarts"] += 1
    _ensure_process()


def _ensure_process() -> None:
    global _proc
    if _proc and _proc.poll() is None:
        return
    import shutil

    node_env = os.environ.get("TECHSCAN_NODE")
    # Prefer explicit TECHSCAN_NODE, otherwise try to resolve 'node' on PATH
    node_path = node_env or shutil.which("node") or shutil.which("node.exe")
    if not node_path:
        logging.getLogger("techscan.persist").warning(
            "Node binary not found in PATH and TECHSCAN_NODE not set; persistent mode disabled"
        )
        return
    server_js = os.path.join(os.path.dirname(__file__), "..", "node_scanner", "server.js")
    server_js = os.path.abspath(server_js)
    if not os.path.exists(server_js):
        logging.getLogger("techscan.persist").error("server.js not found for persistent mode (expected %s)", server_js)
        return
    # Allow increasing Node heap with --max-old-space-size via env (MB)
    max_old = os.environ.get("TECHSCAN_NODE_MAX_OLD_SPACE")
    cmd_base = [node_path]
    if max_old and str(max_old).isdigit():
        cmd_base.append(f"--max-old-space-size={int(max_old)}")
    cmd_base.append(server_js)
    node_cwd = os.path.dirname(server_js)
    # Try a couple of times to start the process (best-effort)
    start_attempts = int(os.environ.get("TECHSCAN_PERSIST_START_ATTEMPTS", "2"))
    backoff = float(os.environ.get("TECHSCAN_PERSIST_START_BACKOFF", "0.4"))
    for attempt in range(1, start_attempts + 1):
        try:
            logging.getLogger("techscan.persist").info(
                "starting persistent scanner daemon (attempt %d/%d): %s", attempt, start_attempts, " ".join(cmd_base)
            )
            _proc = sproc.safe_popen(
                cmd_base, stdin=sproc.PIPE, stdout=sproc.PIPE, stderr=sproc.PIPE, text=True, bufsize=1, cwd=node_cwd
            )
            with _lock:
                _metrics["last_start_ts"] = time.time()
            # start reader threads for stdout/stderr
            threading.Thread(target=_reader_thread, name="techscan-persist-reader", daemon=True).start()
            threading.Thread(target=_stderr_reader_thread, name="techscan-persist-stderr", daemon=True).start()
            # give a small moment for process to initialize
            time.sleep(0.15)
            if _proc and _proc.poll() is None:
                logging.getLogger("techscan.persist").info(
                    "persistent scanner daemon started pid=%s", getattr(_proc, "pid", None)
                )
                # Warmup: Send a ping to ensure browser is actually ready
                try:
                    # Give it a generous 10s to boot the browser for the first time
                    # This prevents the first real scan from timing out
                    logging.getLogger("techscan.persist").info("waiting for browser warmup...")
                    _send({"cmd": "ping", "timeout": 10000}) 
                    logging.getLogger("techscan.persist").info("browser warmup complete")
                except Exception as we:
                    logging.getLogger("techscan.persist").warning("warmup ping failed (ignoring): %s", we)
                return
        except Exception as e:
            logging.getLogger("techscan.persist").warning(
                "failed to start persistent scanner daemon (attempt %d): %s", attempt, e
            )
            try:
                if _proc:
                    _proc.kill()
            except Exception:
                pass
            _proc = None
            time.sleep(backoff)
    logging.getLogger("techscan.persist").error(
        "exhausted persistent scanner start attempts; persistent mode unavailable"
    )


def _stderr_reader_thread():
    """Read stderr lines from the daemon and log them."""
    global _proc
    if not _proc or not _proc.stderr:
        return
    for line in _proc.stderr:
        try:
            logging.getLogger("techscan.persist.stderr").debug(line.rstrip())
        except Exception:
            pass


def _reader_thread():
    if _proc is None or _proc.stdout is None:
        logging.getLogger("techscan.persist").warning("_reader_thread started without active process/stdout")
        return
    for line in _proc.stdout:  # type: ignore
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        _id = msg.get("id")
        if not _id:
            continue
        with _cond:
            _responses[_id] = msg
            _cond.notify_all()


def _send(message: dict) -> dict:
    _ensure_process()
    if _proc is None or _proc.stdin is None:
        raise RuntimeError("persistent process stdin is not available")
    _id = message.get("id") or str(uuid.uuid4())
    message["id"] = _id
    data = json.dumps(message, separators=(",", ":")) + "\n"
    started = time.time()
    try:
        _proc.stdin.write(data)
        _proc.stdin.flush()
    except Exception as e:
        # Count as failure and maybe restart
        _fail_window.append(time.time())
        with _lock:
            _metrics["failures"] += 1
        _watchdog_check()
        raise RuntimeError(f"failed writing to persistent process: {e}")
    # wait
    deadline = time.time() + float(os.environ.get("TECHSCAN_PERSIST_TIMEOUT", "70"))
    with _cond:
        while _id not in _responses and time.time() < deadline:
            _cond.wait(timeout=1)
        resp = _responses.pop(_id, None)
    if not resp:
        _fail_window.append(time.time())
        with _lock:
            _metrics["timeouts"] += 1
        _watchdog_check()
        raise TimeoutError("persistent scanner timeout waiting response")
    elapsed_ms = int((time.time() - started) * 1000)
    with _lock:
        _metrics["requests"] += 1
        if not resp.get("ok"):
            _metrics["failures"] += 1
        else:
            _metrics["latency_ms_total"] += elapsed_ms
            _metrics["latency_ms_count"] += 1
    return resp


def scan(domain: str, full: bool = False) -> dict:
    url = domain
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    # Concurrency limiting: guard calls to daemon
    with _sem:
        resp = _send({"cmd": "scan", "url": url, "full": full})
    if not resp.get("ok"):
        _fail_window.append(time.time())
        _watchdog_check()
        raise RuntimeError(resp.get("error") or "scan failed")
    return resp["result"]


def ping() -> dict:
    return _send({"cmd": "ping"})


def shutdown() -> None:
    try:
        _send({"cmd": "shutdown"})
    except Exception:
        pass


def get_metrics_snapshot() -> Dict[str, Any]:
    with _lock:
        avg_latency = 0
        if _metrics["latency_ms_count"]:
            avg_latency = _metrics["latency_ms_total"] / _metrics["latency_ms_count"]
        return {
            "requests": _metrics["requests"],
            "failures": _metrics["failures"],
            "timeouts": _metrics["timeouts"],
            "restarts": _metrics["restarts"],
            "last_start_ts": _metrics["last_start_ts"],
            "avg_latency_ms": round(avg_latency, 2),
            "inflight_fail_window": len(_fail_window),
        }
