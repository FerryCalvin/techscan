from __future__ import annotations

from flask import Blueprint, request, jsonify, current_app, Response
import logging, time, os, threading, json, math
from datetime import datetime
from ..scan_utils import (
    get_cached_or_scan,
    scan_bulk,
    DOMAIN_RE,
    extract_host,
    extract_url_with_path,
    snapshot_cache,
    validate_domain,
    quick_single_scan,
    deep_scan,
    scan_unified,
    bulk_quick_then_deep,
    fast_full_scan,
    scan_domain,
    synthetic_header_detection,
)
from .. import version_audit
from .. import db as _db
from .. import bulk_store  # kept for legacy/csv helpers if needed, but storage moved to DB
from .. import queue as _queue
from .. import tasks as _tasks
import uuid
from flask_limiter import Limiter

bp = Blueprint("scan", __name__)

# Alias at module level to avoid accidental shadowing inside functions
deep_scan_fn = deep_scan

# Alias at module scope to avoid accidental function-local shadowing which can
# trigger UnboundLocalError when Python marks the name as local in a function.
deep_scan_fn = deep_scan

_cancelled_tokens: dict[str, float] = {}
_cancel_lock = threading.Lock()
_CANCEL_TOKEN_TTL = 300.0


def _estimate_payload_bytes(payload: dict | list | None) -> int | None:
    if payload is None:
        return None
    try:
        return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except Exception:
        logging.getLogger("techscan.scan").debug("failed to estimate payload size", exc_info=True)
        return None


def _coerce_timestamp(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            coerced = float(value)
        except (TypeError, ValueError):
            return None
        return coerced if math.isfinite(coerced) else None
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            coerced = float(stripped)
            return coerced if math.isfinite(coerced) else None
        except ValueError:
            try:
                iso_formatted = stripped.replace("Z", "+00:00") if stripped.endswith("Z") else stripped
                return datetime.fromisoformat(iso_formatted).timestamp()
            except ValueError:
                return None
    return None


def _register_cancel_tokens(tokens: list[str] | tuple[str, ...]) -> None:
    if not tokens:
        return
    now = time.time()
    with _cancel_lock:
        for token in tokens:
            if not token:
                continue
            _cancelled_tokens[str(token)] = now
        stale = [tok for tok, ts in _cancelled_tokens.items() if now - ts > _CANCEL_TOKEN_TTL]
        for tok in stale:
            _cancelled_tokens.pop(tok, None)


def _consume_cancel_token(token: str | None) -> bool:
    if not token:
        return False
    now = time.time()
    with _cancel_lock:
        ts = _cancelled_tokens.pop(token, None)
        if ts is None:
            stale = [tok for tok, val in _cancelled_tokens.items() if now - val > _CANCEL_TOKEN_TTL]
            for tok in stale:
                _cancelled_tokens.pop(tok, None)
            return False
    return True


def _apply_low_tech_rescue(domain: str, wappalyzer_path: str, result: dict, current_count: int) -> bool:
    """If enabled, run one more persistent scan when tech count is too low.

    Returns True when the fallback added more technologies to the result.
    """
    if not isinstance(result, dict):
        return False
    if os.environ.get("TECHSCAN_LOW_TECH_RETRY", "1") != "1":
        return False
    try:
        threshold = int(os.environ.get("TECHSCAN_LOW_TECH_THRESHOLD", "15") or "15")
    except ValueError:
        threshold = 1
    if current_count > threshold:
        return False
    try:
        fallback_timeout = int(os.environ.get("TECHSCAN_LOW_TECH_TIMEOUT_S", "15") or "15")
    except ValueError:
        fallback_timeout = 15
    use_best_snapshot = os.environ.get("TECHSCAN_LOW_TECH_BEST_FALLBACK", "1") == "1"
    logger = logging.getLogger("techscan.scan")
    try:
        fallback = scan_domain(domain, wappalyzer_path, timeout=fallback_timeout, retries=0, full=True)
    except Exception as err:
        logger.warning("low-tech fallback scan failed domain=%s err=%s", domain, err)
        return False
    fallback_techs = fallback.get("technologies") or []
    if len(fallback_techs) <= current_count:
        logger.debug(
            "low-tech fallback added no new technologies domain=%s base=%d fallback=%d",
            domain,
            current_count,
            len(fallback_techs),
        )
        if use_best_snapshot:
            best_payload = _load_best_scan_payload(domain)
            if best_payload:
                best_techs = best_payload.get("technologies") or []
                if len(best_techs) > current_count:
                    logger.info(
                        "low-tech best snapshot fallback domain=%s best=%d current=%d",
                        domain,
                        len(best_techs),
                        current_count,
                    )
                    result["technologies"] = best_techs
                    if best_payload.get("raw"):
                        result["raw"] = best_payload["raw"]
                    if best_payload.get("payload_bytes") is not None:
                        result["payload_bytes"] = best_payload["payload_bytes"]
                    if best_payload.get("mode"):
                        result["mode"] = best_payload["mode"]
                    if best_payload.get("duration") is not None:
                        result["duration"] = best_payload["duration"]
                    if best_payload.get("started_at") is not None:
                        result["started_at"] = best_payload["started_at"]
                    if best_payload.get("finished_at") is not None:
                        result["finished_at"] = best_payload["finished_at"]
                    result.setdefault("phases", {})["low_tech_rescue"] = "best_snapshot"
                    result["fallback_engine"] = "best_snapshot"
                    return True
        return False
    logger.info("low-tech fallback added %d technologies domain=%s", len(fallback_techs) - current_count, domain)
    result["technologies"] = fallback_techs
    if fallback.get("categories"):
        result["categories"] = fallback.get("categories")
    if fallback.get("raw"):
        result["raw"] = fallback.get("raw")
    result.setdefault("phases", {})["low_tech_rescue"] = "full_scan"
    result["fallback_engine"] = fallback.get("engine")
    return True


def _ensure_serializable(obj):
    """Recursively ensure all dict keys are strings to prevent JSON sort_keys crashes (int vs str comparisons)."""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            new_key = str(k)
            new_obj[new_key] = _ensure_serializable(v)
        return new_obj
    elif isinstance(obj, list):
        return [_ensure_serializable(item) for item in obj]
    return obj


def _load_best_scan_payload(domain: str) -> dict | None:
    """Fetch the best historical scan for a domain (highest tech_count)."""
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                        SELECT id, mode, started_at, finished_at, duration_ms, from_cache, retries, timeout_used,
                               technologies_json, raw_json, payload_bytes
                        FROM scans
                        WHERE domain=%s
                        ORDER BY COALESCE(tech_count, 0) DESC, finished_at DESC
                        LIMIT 1
                    """,
                    (domain,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                techs = row[8] if isinstance(row[8], list) else []
                payload = {
                    "domain": domain,
                    "scan_id": row[0],
                    "mode": row[1],
                    "started_at": row[2].timestamp() if getattr(row[2], "timestamp", None) else None,
                    "finished_at": row[3].timestamp() if getattr(row[3], "timestamp", None) else None,
                    "duration": round((row[4] or 0) / 1000.0, 3) if row[4] is not None else None,
                    "from_cache": row[5],
                    "retries": row[6],
                    "timeout_used": row[7],
                    "technologies": techs,
                    "tech_count": len(techs),
                }
                if len(row) > 9 and isinstance(row[9], dict):
                    payload["raw"] = row[9]
                if len(row) > 10 and row[10] is not None:
                    payload["payload_bytes"] = row[10]
                return payload
    except Exception:
        logging.getLogger("techscan.scan").debug("best scan lookup failed domain=%s", domain, exc_info=True)
    return None


def _ensure_minimum_detection(domain: str, result: dict) -> bool:
    """Guarantee at least one technology entry when scanners return empty.

    Tries heuristic_fast first (cheap HTML fetch) then synthetic header detection.
    Returns True if technologies were injected.
    """
    if os.environ.get("TECHSCAN_ENSURE_MIN_TECH", "1") != "1":
        return False
    if not isinstance(result, dict):
        return False
    techs = result.get("technologies")
    if isinstance(techs, list) and any((t or {}).get("name") for t in techs):
        return False
    logger = logging.getLogger("techscan.scan")
    # Stage 1: heuristic quick probe (reuse tier-0 logic)
    try:
        from .. import heuristic_fast

        try:
            budget_ms = int(os.environ.get("TECHSCAN_MIN_TECH_HEURISTIC_MS", "1200") or "1200")
        except ValueError:
            budget_ms = 1200
        hres = heuristic_fast.run_heuristic(domain, budget_ms=max(600, min(budget_ms, 2000)), allow_empty_early=True)
        htechs = [t for t in (hres.get("technologies") or []) if t.get("name")]
        if htechs:
            result["technologies"] = htechs
            if hres.get("categories"):
                result["categories"] = hres["categories"]
            meta = result.setdefault("phases", {})
            meta["minimum_detection"] = "heuristic"
            tier = result.setdefault("tiered", {})
            tier["minimum_detection"] = "heuristic"
            logger.info("minimum detection heuristic added %d technologies domain=%s", len(htechs), domain)
            return True
    except Exception as err:
        logger.debug("minimum detection heuristic failed domain=%s err=%s", domain, err)
    # Stage 2: server header fallback via synthetic HEAD probe
    try:
        synth_timeout = 3
        try:
            synth_timeout = max(1, int(os.environ.get("TECHSCAN_MIN_TECH_SYNTH_TIMEOUT", "3") or "3"))
        except ValueError:
            synth_timeout = 3
        synth = synthetic_header_detection(domain, timeout=synth_timeout)
        synth = [t for t in synth if t.get("name")]
        if synth:
            result["technologies"] = synth
            cats = result.setdefault("categories", {})
            for tech in synth:
                for cat in tech.get("categories") or []:
                    bucket = cats.setdefault(cat, [])
                    if not any(b["name"] == tech["name"] and b.get("version") == tech.get("version") for b in bucket):
                        bucket.append({"name": tech["name"], "version": tech.get("version")})
            meta = result.setdefault("phases", {})
            meta["minimum_detection"] = "synthetic"
            tier = result.setdefault("tiered", {})
            tier["minimum_detection"] = "synthetic"
            logger.info("minimum detection synthetic headers added %d technologies domain=%s", len(synth), domain)
            return True
    except Exception as err:
        logger.debug("minimum detection synthetic failed domain=%s err=%s", domain, err)
    return False


# Custom limits (can be overridden via env)
BULK_LIMIT = os.environ.get("TECHSCAN_BULK_RATE_LIMIT", "20 per minute")
SINGLE_LIMIT = os.environ.get("TECHSCAN_SINGLE_RATE_LIMIT", "120 per minute")


def limit_decorator():
    limiter: Limiter = current_app.extensions.get("limiter")  # type: ignore
    return limiter


@bp.route("/scan", methods=["POST", "GET"])
def _scan_rate_wrapper():
    limiter = current_app.extensions.get("limiter")
    if limiter:
        # apply limit manually (since blueprint-level decorator sometimes loads before limiter)
        @limiter.limit(SINGLE_LIMIT)
        def inner():
            return scan_single_impl()

        return inner()
    return scan_single_impl()


def scan_single_impl():
    # Support both JSON POST and simple GET query form
    if request.method == "GET":
        data = {
            "domain": request.args.get("domain") or request.args.get("d"),
            "timeout": request.args.get("timeout"),
            "retries": request.args.get("retries"),
            "ttl": request.args.get("ttl"),
            "full": request.args.get("full"),
            "deep": request.args.get("deep"),
            "fast_full": request.args.get("fast_full"),
            "fresh": request.args.get("fresh"),
            "quick": request.args.get("quick"),
        }
    else:
        data = request.get_json(silent=True) or {}
    start = time.time()
    # Optional per-request debug escalation (?debug=1) without restarting service
    debug_escalated = False
    if request.args.get("debug") == "1" or str((data or {}).get("debug")).lower() in ("1", "true", "yes"):
        root_logger = logging.getLogger()
        if root_logger.level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            logging.getLogger("techscan.scan").debug("per-request debug escalation active")
            debug_escalated = True
    if data is None or not isinstance(data, dict):
        return jsonify({"error": "invalid JSON body"}), 400
    raw_input = (data.get("domain") or "").strip()
    client_request_id = str(data.get("client_request_id") or request.args.get("client_request_id") or "").strip()
    client_context = str(data.get("client_context") or request.args.get("client_context") or "").strip()
    domain = extract_host(raw_input)  # host-only for validation and scanning
    domain_with_path = extract_url_with_path(raw_input)  # full URL with path for storage
    timeout = int(data.get("timeout") or 45)
    retries = int(data.get("retries") or 0)
    ttl = data.get("ttl")
    full = bool(data.get("full") or False)
    deep = bool(data.get("deep") or False)
    fast_full = bool(data.get("fast_full") or False)
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    fresh = bool(data.get("fresh") or False)
    logging.getLogger("techscan.scan").info(
        "/scan request input=%s domain=%s timeout=%s retries=%s fresh=%s ttl=%s full=%s deep=%s fast_full=%s",
        raw_input,
        domain,
        timeout,
        retries,
        fresh,
        ttl_int,
        full,
        deep,
        fast_full,
    )
    if not raw_input:
        return jsonify({"error": "missing domain field"}), 400
    try:
        domain = validate_domain(domain)
    except ValueError:
        logging.getLogger("techscan.scan").warning(
            "/scan invalid domain input=%r parsed=%r bytes=%s", raw_input, domain, "-".join(str(ord(c)) for c in domain)
        )
        return jsonify({"error": "invalid domain format"}), 400
    wpath = current_app.config["WAPPALYZER_PATH"]
    # Local alias to avoid accidental name-shadowing causing UnboundLocalError
    deep_scan_fn = deep_scan
    quick_flag = False
    # quick mode precedence: body.quick, query quick=1, or env TECHSCAN_QUICK_SINGLE=1
    if (
        str(data.get("quick")).lower() in ("1", "true", "yes")
        or request.args.get("quick") == "1"
        or os.environ.get("TECHSCAN_QUICK_SINGLE", "0") == "1"
    ):
        quick_flag = True
    defer_quick = os.environ.get("TECHSCAN_QUICK_DEFER_FULL", "0") == "1"
    unified_enabled = os.environ.get("TECHSCAN_UNIFIED", "1") == "1"
    force_unified_flag = unified_enabled and str(os.environ.get("TECHSCAN_FORCE_UNIFIED", "1")).lower() not in (
        "0",
        "false",
        "no",
    )

    def run_unified_scan(reason: str, min_budget_ms: int = 6000, fallback=None):
        try:
            budget_ms = max(min_budget_ms, int(timeout) * 1000)
        except Exception:
            budget_ms = min_budget_ms
        logging.getLogger("techscan.scan").info(
            "%s: using unified pipeline budget_ms=%s domain=%s", reason, budget_ms, domain
        )
        try:
            return scan_unified(domain, wpath, budget_ms=budget_ms)
        except Exception as ue:
            logging.getLogger("techscan.scan").warning(
                "unified pipeline failed (%s) domain=%s err=%s", reason, domain, ue
            )
            if callable(fallback):
                return fallback()
            raise

    if force_unified_flag:
        quick_flag = False
        full = True
    try:
        # If the request explicitly asks for a specific mode, respect it.
        # Otherwise prefer the more-complete deep/full path when unified mode is enabled
        # or when TECHSCAN_FORCE_FULL is set. This makes the scanner return the most
        # comprehensive detection by default after restarts.
        force_full_env = os.environ.get("TECHSCAN_FORCE_FULL", "0") == "1"
        if fast_full:
            result = fast_full_scan(domain, wpath)
        elif force_unified_flag:
            result = run_unified_scan(
                "force-unified", min_budget_ms=20000, fallback=lambda: deep_scan_fn(domain, wpath)
            )
        elif deep or force_full_env:
            if unified_enabled or force_unified_flag:
                result = run_unified_scan(
                    "deep-request", min_budget_ms=20000, fallback=lambda: deep_scan_fn(domain, wpath)
                )
            else:
                result = deep_scan_fn(domain, wpath)
        elif quick_flag and not force_full_env and not force_unified_flag:
            result = quick_single_scan(
                domain, wpath, defer_full=defer_quick, timeout_full=timeout, retries_full=retries
            )
        else:
            # Prefer unified/deep by default for completeness when unified mode enabled
            if unified_enabled or force_full_env or force_unified_flag:
                result = run_unified_scan(
                    "default",
                    min_budget_ms=20000,
                    fallback=lambda: get_cached_or_scan(
                        domain, wpath, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full
                    ),
                )
            else:
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.getLogger("techscan.scan").debug(
                        "quick_flag_evaluation quick_flag=%s body.quick=%r env.TECHSCAN_QUICK_SINGLE=%s args.quick=%s",
                        quick_flag,
                        data.get("quick"),
                        os.environ.get("TECHSCAN_QUICK_SINGLE", "0"),
                        request.args.get("quick"),
                    )
                result = get_cached_or_scan(
                    domain, wpath, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full
                )
        # Backward compat: ensure started_at/finished_at appear (cache hit may lack them)
        if "started_at" not in result:
            result["started_at"] = result.get("timestamp")
        if "finished_at" not in result:
            result["finished_at"] = int(time.time())
        # Ensure version evidence is applied even when payload comes from cache/DB
        try:
            if os.environ.get("TECHSCAN_VERSION_EVIDENCE", "1") == "1":
                version_audit.apply_version_evidence(result)
        except Exception:
            logging.getLogger("techscan.scan").debug("version evidence apply failed", exc_info=True)
        # Observability: warn if scan returned very few technologies
        try:
            techs_check = result.get("technologies") or []
            low_thresh = 3
            try:
                low_thresh = int(os.environ.get("TECHSCAN_LOW_TECH_THRESHOLD", "15") or "15")
            except ValueError:
                low_thresh = 3
            if isinstance(techs_check, list) and len(techs_check) <= low_thresh:
                logging.getLogger("techscan.scan").warning(
                    "Low tech count (%d) for domain=%s engine=%s phases=%s",
                    len(techs_check),
                    domain,
                    result.get("engine"),
                    result.get("phases"),
                )
                _apply_low_tech_rescue(domain, wpath, result, len(techs_check))
            _ensure_minimum_detection(domain, result)
        except Exception:
            logging.getLogger("techscan.scan").debug("low tech count check failed", exc_info=True)
        # Performance summary log (optional)
        if os.environ.get("TECHSCAN_PERF_LOG", "0") == "1":
            try:
                techs = result.get("technologies") or []
                tech_count = len(techs)
                with_version = sum(1 for t in techs if t.get("version"))
                phases = result.get("phases") or {}
                tiered = result.get("tiered") or {}
                logger = logging.getLogger("techscan.perf")
                # Keep it compact key=value pairs on one line
                parts = [
                    f"domain={domain}",
                    f"engine={result.get('engine')}",
                    f"mode={result.get('scan_mode')}",
                    f"tech={tech_count}",
                    f"with_ver={with_version}",
                    f"duration_s={result.get('duration')}",
                    f"cached={result.get('cached', False)}",
                ]
                for k in ("heuristic_ms", "synthetic_ms", "micro_ms", "node_full_ms", "engine_ms", "version_audit_ms"):
                    if k in phases:
                        parts.append(f"{k}={phases.get(k)}")
                if "micro_used" in tiered:
                    parts.append(f"micro_used={bool(tiered.get('micro_used'))}")
                if "node_full_used" in tiered:
                    parts.append(f"node_full_used={bool(tiered.get('node_full_used'))}")
                if "retries" in result:
                    parts.append(f"retries={result.get('retries')}")
                if result.get("adaptive_timeout"):
                    parts.append("adaptive=1")
                logger.info("[perf] " + " ".join(parts))
            except Exception:
                logging.getLogger("techscan.scan").debug("failed building perf log parts", exc_info=True)
        if client_request_id and _consume_cancel_token(client_request_id):
            logging.getLogger("techscan.scan").info(
                "/scan client_cancel domain=%s request_id=%s context=%s",
                domain,
                client_request_id,
                client_context or "n/a",
            )
            if debug_escalated:
                try:
                    base_level_name = os.environ.get("TECHSCAN_LOG_LEVEL", "INFO").upper()
                    base_level = getattr(logging, base_level_name, logging.INFO)
                    logging.getLogger().setLevel(base_level)
                except Exception:
                    logging.getLogger("techscan.scan").debug(
                        "failed to restore log level after cancel acknowledgement", exc_info=True
                    )
            return jsonify({"domain": domain, "status": "cancelled", "error": "client_cancelled"})

        raw_payload = result.get("raw") if isinstance(result, dict) else None
        payload_bytes = _estimate_payload_bytes(raw_payload)
        if payload_bytes is not None:
            result["payload_bytes"] = payload_bytes
        now = time.time()
        started_at = _coerce_timestamp(result.get("started_at"))
        if started_at is None:
            started_at = _coerce_timestamp(result.get("timestamp"))
        finished_at = _coerce_timestamp(result.get("finished_at"))

        existing_duration = None
        if "duration" in result:
            try:
                existing_duration = float(result["duration"])
                if existing_duration < 0 or not math.isfinite(existing_duration):
                    existing_duration = None
            except (TypeError, ValueError):
                existing_duration = None

        derived_duration = None
        if started_at is not None and finished_at is not None:
            try:
                derived_duration = max(0.0, float(finished_at) - float(started_at))
            except Exception:
                derived_duration = None

        duration = None
        if derived_duration is not None and derived_duration > 0:
            duration = derived_duration
        elif existing_duration is not None and existing_duration > 0:
            duration = existing_duration
            if finished_at is None:
                finished_at = now
            if started_at is None:
                started_at = finished_at - duration
        else:
            if finished_at is None:
                finished_at = now
            if started_at is None:
                started_at = finished_at
            duration = 0.0

        # Guard against negative spacing due to inconsistent timestamps
        if finished_at < started_at:
            if duration and duration > 0:
                # Align start time using available duration
                started_at = finished_at - duration
            else:
                finished_at = started_at
                duration = 0.0

        result["started_at"] = started_at
        result["finished_at"] = finished_at
        result["duration"] = duration
        logging.getLogger("techscan.scan").info(
            "/scan success domain=%s quick=%s deep=%s fast_full=%s duration=%.2fs retries_used=%s payload_bytes=%s",
            domain,
            quick_flag,
            deep,
            fast_full,
            time.time() - start,
            result.get("retries", 0),
            payload_bytes if payload_bytes is not None else "n/a",
        )
        if debug_escalated:
            # Revert to original level (INFO by default)
            try:
                base_level_name = os.environ.get("TECHSCAN_LOG_LEVEL", "INFO").upper()
                base_level = getattr(logging, base_level_name, logging.INFO)
                logging.getLogger().setLevel(base_level)
            except Exception:
                logging.getLogger("techscan.scan").debug("failed to restore log level after /scan", exc_info=True)
        # Persist scan (best-effort) if DB enabled
        try:
            meta_for_db = {
                "domain": domain_with_path,  # Use full URL with path
                "scan_mode": result.get("engine")
                or (
                    "fast_full"
                    if fast_full
                    else "deep"
                    if deep
                    else "quick"
                    if quick_flag
                    else ("full" if full else "fast")
                ),
                "started_at": started_at,
                "finished_at": finished_at,
                "duration": duration,
                "technologies": result.get("technologies"),
                "categories": result.get("categories"),
                "raw": result.get("raw"),
                "retries": result.get("retries", 0),
                "adaptive_timeout": result.get("phases", {}).get("adaptive"),
                "error": result.get("error"),
                "payload_bytes": payload_bytes,
            }
            timeout_used = 0
            # Derive timeout used if present in phases metadata
            phases = result.get("phases") or {}
            for k in ("full_budget_ms", "timeout_ms", "budget_ms"):
                if k in phases:
                    try:
                        timeout_used = int(phases[k])
                        break
                    except Exception:
                        logging.getLogger("techscan.scan").debug(
                            "failed to parse timeout_used from phases", exc_info=True
                        )
            _db.save_scan(meta_for_db, result.get("cached", False), timeout_used)
        except Exception as persist_ex:
            logging.getLogger("techscan.scan").warning("persist_failed domain=%s err=%s", domain, persist_ex)

        try:
            return jsonify(_ensure_serializable(result))
        except Exception as js_err:
            # Last resort fallback if simple recursion failed (e.g. cycles, though unlikely in JSON)
            logging.getLogger("techscan.scan").error("serializers fail domain=%s err=%s", domain, js_err)
            return jsonify({"domain": domain, "error": "serialization_failed", "details": str(js_err)}), 500

    except Exception as e:
        # Log full traceback to help diagnose UnboundLocalError or other issues
        import traceback as _tb

        tb = _tb.format_exc()
        logging.getLogger("techscan.scan").exception("/scan error domain=%s err=%s\n%s", domain, e, tb)
        # Attempt to log failed attempt as scan row too (with error) before returning
        try:
            _db.save_scan(
                {
                    "domain": domain_with_path,  # Use full URL with path
                    "scan_mode": "error",
                    "started_at": start,
                    "finished_at": time.time(),
                    "duration": time.time() - start,
                    "technologies": [],
                    "categories": {},
                    "raw": None,
                    "retries": 0,
                    "error": str(e),
                },
                from_cache=False,
                timeout_used=0,
            )
        except Exception:
            logging.getLogger("techscan.scan").debug("failed to persist error scan row", exc_info=True)
        # Return traceback in response for easier local debugging (remove in production)
        try:
            return jsonify({"domain": domain, "error": str(e), "traceback": tb}), 500
        except Exception:
            return jsonify({"domain": domain, "error": str(e)}), 500


@bp.route("/bulk", methods=["POST"])
def bulk_rate_wrapper():
    limiter = current_app.extensions.get("limiter")
    if limiter:

        @limiter.limit(BULK_LIMIT)
        def inner():
            return scan_bulk_route_impl()

        return inner()
    return scan_bulk_route_impl()


# BULK_NATIVE_ENHANCED
def scan_bulk_route_impl():
    """Native enhanced bulk route (batch_id retrieval, CSV export, cached_only, error_summary).
    Query / body parameters:
      domains: list[str]
      batch_id: retrieve previously stored batch (no new scan)
      format: json|csv
      cached_only: 1 -> CSV from cache (no scan)
      include_raw: 1 -> include raw JSON column in CSV
    """
    data = request.get_json(silent=True) or {}
    time.time()
    if request.args.get("debug") == "1" or (
        isinstance(data, dict) and str(data.get("debug")).lower() in ("1", "true", "yes")
    ):
        root_logger = logging.getLogger()
        if root_logger.level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            logging.getLogger("techscan.bulk").debug("per-request debug escalation active")
    batch_id_req = request.args.get("batch_id") or data.get("batch_id")
    out_format = (request.args.get("format") or data.get("format") or "json").lower()
    include_raw = (request.args.get("include_raw") == "1") or bool(data.get("include_raw"))
    cached_only = (request.args.get("cached_only") == "1") or bool(data.get("cached_only"))

    # Retrieval path (from DB scan_jobs)
    if batch_id_req:
        job_row = None
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, results, error, created_at, finished_at FROM scan_jobs WHERE id=%s", (batch_id_req,)
                )
                job_row = cur.fetchone()

        if not job_row:
            # Fallback to legacy in-memory store for transition or check if it returns 404
            meta = bulk_store.get_batch(batch_id_req)
            if not meta:
                return jsonify({"error": "batch_id not found", "batch_id": batch_id_req}), 404
            results = meta["results"]
        else:
            status, results, error, created, finished = job_row
            results = results or []
            if status == "failed":
                return jsonify({"batch_id": batch_id_req, "status": "failed", "error": error}), 500
            elif status != "completed":
                return jsonify({"batch_id": batch_id_req, "status": status, "progress": "running"}), 202

        ok = sum(1 for r in results if r and r.get("status") == "ok")
        buckets = {"timeout": 0, "dns": 0, "ssl": 0, "connection": 0, "other": 0}
        for r in results:
            if not r or r.get("status") == "ok":
                continue
            err = (r.get("error") or "").lower()
            if "timeout" in err or "timed out" in err:
                buckets["timeout"] += 1
            elif "dns" in err or "nodename" in err:
                buckets["dns"] += 1
            elif "ssl" in err or "cert" in err:
                buckets["ssl"] += 1
            elif "connection" in err or "refused" in err or "unreachable" in err:
                buckets["connection"] += 1
            else:
                buckets["other"] += 1
        if out_format == "csv":
            import csv, io, json as _json

            output = io.StringIO()
            fieldnames = [
                "status",
                "domain",
                "timestamp",
                "tech_count",
                "payload_bytes",
                "technologies",
                "categories",
                "cached",
                "duration",
                "retries",
                "engine",
                "error",
                "outdated_count",
                "outdated_list",
            ]
            if include_raw:
                fieldnames.append("raw")
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                if not r:
                    continue
                if r.get("status") != "ok":
                    row_err = {k: r.get(k) for k in ["status", "domain", "error"]}
                    writer.writerow(row_err)
                    continue
                techs = r.get("technologies") or []
                tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get("version") else "") for t in techs]
                categories = sorted((r.get("categories") or {}).keys())
                audit_meta = r.get("audit") or {}
                outdated_items = audit_meta.get("outdated") or []
                outdated_list_str = " | ".join(
                    f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items
                )
                row = {
                    "status": r.get("status"),
                    "domain": r.get("domain"),
                    "timestamp": r.get("timestamp"),
                    "tech_count": len(techs),
                    "technologies": " | ".join(tech_list),
                    "categories": " | ".join(categories),
                    "cached": r.get("cached"),
                    "duration": r.get("duration"),
                    "retries": r.get("retries", 0),
                    "engine": r.get("engine"),
                    "error": r.get("error"),
                    "outdated_count": audit_meta.get("outdated_count"),
                    "outdated_list": outdated_list_str,
                }
                if include_raw:
                    row["raw"] = _json.dumps(r.get("raw"), ensure_ascii=False)
                writer.writerow(row)
            csv_data = output.getvalue()
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=bulk_batch_{batch_id_req}.csv"},
            )
        return jsonify(
            {
                "count": len(results),
                "ok": ok,
                "batch_id": batch_id_req,
                "error_summary": buckets,
                "results": results,
                "retrieved": True,
            }
        )

    # cached_only CSV path (no re-scan) - UNCHANGED
    if out_format == "csv" and cached_only:
        domains = data.get("domains") or []
        if not isinstance(domains, list):
            return jsonify({"error": "domains field must be a list"}), 400
        from ..scan_utils import snapshot_cache as _snapshot_cache

        cache_rows = _snapshot_cache(domains)
        best = {}
        for r in cache_rows:
            dom = r.get("domain")
            if not dom:
                continue
            prev = best.get(dom)
            if not prev or (r.get("scan_mode") == "full" and prev.get("scan_mode") != "full"):
                best[dom] = r
        import csv, io, json as _json

        output = io.StringIO()
        fieldnames = [
            "status",
            "domain",
            "timestamp",
            "tech_count",
            "payload_bytes",
            "technologies",
            "categories",
            "cached",
            "duration",
            "retries",
            "engine",
            "error",
            "outdated_count",
            "outdated_list",
        ]
        if include_raw:
            fieldnames.append("raw")
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        now_ts = int(time.time())
        for d in domains:
            dom_l = (d or "").strip().lower()
            r = best.get(dom_l)
            if not r:
                writer.writerow({"status": "missing", "domain": dom_l})
                continue
            techs = r.get("technologies") or []
            tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get("version") else "") for t in techs]
            categories = sorted((r.get("categories") or {}).keys())
            audit_meta = r.get("audit") or {}
            outdated_items = audit_meta.get("outdated") or []
            outdated_list_str = " | ".join(
                f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items
            )
            row = {
                "status": "ok",
                "domain": dom_l,
                "timestamp": r.get("timestamp") or now_ts,
                "tech_count": len(techs),
                "payload_bytes": r.get("payload_bytes"),
                "technologies": " | ".join(tech_list),
                "categories": " | ".join(categories),
                "cached": True,
                "duration": r.get("duration"),
                "retries": r.get("retries", 0),
                "engine": r.get("engine"),
                "error": r.get("error"),
                "outdated_count": audit_meta.get("outdated_count"),
                "outdated_list": outdated_list_str,
            }
            if include_raw:
                row["raw"] = _json.dumps(r.get("raw"), ensure_ascii=False)
            writer.writerow(row)
        csv_data = output.getvalue()
        return Response(
            csv_data, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=bulk_cached.csv"}
        )

    # New scan path via RQ
    data = request.get_json(silent=True) or {}
    domains = data.get("domains") or []
    if not isinstance(domains, list):
        return jsonify({"error": "domains field must be a list"}), 400
    if not domains:
        return jsonify({"error": "domains list empty"}), 400

    timeout = int(data.get("timeout") or 30)
    retries = int(data.get("retries") or 2)
    ttl = data.get("ttl")
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    full = bool(data.get("full") or False)
    two_phase = bool(data.get("two_phase") or (request.args.get("two_phase") == "1"))
    fallback_quick = bool(data.get("fallback_quick") or (request.args.get("fallback_quick") == "1"))
    if not fallback_quick and os.environ.get("TECHSCAN_BULK_FALLBACK_QUICK_DEFAULT", "0") == "1":
        fallback_quick = True
    fresh = bool(data.get("fresh") or False)
    concurrency = int(data.get("concurrency") or 4)
    wpath = current_app.config["WAPPALYZER_PATH"]

    # Enqueue job
    job_id = uuid.uuid4().hex
    params = {
        "wappalyzer_path": wpath,
        "concurrency": concurrency,
        "timeout": timeout,
        "retries": retries,
        "fresh": fresh,
        "ttl": ttl_int,
        "full": full,
        "two_phase": two_phase,
        # fallback_quick is handled inside task logic currently or could be passed.
        # But for now task uses simplified params.
        # Ideally we update task to handle fallback_quick too.
    }

    # Create DB entry
    import json as _json_mod

    with _db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_jobs (id, type, status, domains, options, total)
                VALUES (%s, 'bulk', 'pending', %s::jsonb, %s::jsonb, %s)
            """,
                (job_id, _json_mod.dumps(domains), _json_mod.dumps(params), len(domains)),
            )
        conn.commit()

    # Fallback to synchronous execution if RQ disabled or unavailable
    if os.environ.get("TECHSCAN_DISABLE_RQ") == "1" or not _queue.is_available():
        logging.getLogger("techscan.bulk").warning(
            "RQ disabled/unavailable, running bulk scan synchronously job=%s", job_id
        )
        time.time()
        try:
            # Note: two_phase logic (bulk_quick_then_deep) returns a list
            # simple scan_bulk also returns a list
            # We must map input params correctly
            if two_phase:
                results = bulk_quick_then_deep(domains, wpath, concurrency=concurrency)
            else:
                # fallback_quick logic must be handled. scan_bulk in core logic doesn't support fallback_quick arg directly in signature shown?
                # But test expects scan_bulk to NOT return 'deep-combined' maybe?
                # Actually, test passes fallback_quick=1. If we use scan_bulk, does it fallback?
                # Let's inspect get_cached_or_scan args. It takes 'timeout'.
                # core.scan_bulk calls get_cached_or_scan.
                # If fallback_quick is passed to route, we should probably forward it if possible, or assume scan_bulk handles it?
                # core.scan_bulk def: (..., fresh=False, ttl=None, full=False)
                # It does NOT take fallback_quick.
                # However, test_bulk_fallback_quick expects DIFFERENT behavior than standard.
                # If we assume fallback_quick means "if fast fails, don't do deep"? No, "fallback quick" usually means "if deep fails, return quick".
                # My fast_full_scan logic has fallback.
                # But scan_bulk calls get_cached_or_scan -> scan_domain.
                # Let's look at the test again. It expects 'heuristic-quick' engine for the timeout domain.
                # This implies the scanner fell back to heuristic/quick when full/bulk failed.
                # We need to manually handle this if core doesn't.
                # Or, if fallback_quick=1, maybe we use 'fast_full_scan' via some option?
                # scan_bulk signature: full=bool.
                # If fallback_quick is True, maybe we should perform a manual quick scan for errors?
                results = scan_bulk(
                    domains,
                    wpath,
                    concurrency=concurrency,
                    timeout=timeout,
                    retries=retries,
                    fresh=fresh,
                    ttl=ttl_int,
                    full=full,
                )

                if fallback_quick:
                    from ..scanners.core import quick_single_scan

                    # Post-process results: if error or timeout, try quick scan
                    for idx, res in enumerate(results):
                        if res.get("status") == "error" or res.get("error"):
                            try:
                                # Fallback to quick
                                fb = quick_single_scan(res["domain"], wpath)
                                fb["fallback"] = "quick"
                                fb["original_error"] = res.get("error") or res.get("status")
                                results[idx] = fb
                            except Exception:
                                pass
            # Update DB
            with _db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE scan_jobs SET status='completed', results=%s::jsonb, finished_at=NOW() WHERE id=%s",
                        (_json_mod.dumps(results), job_id),
                    )
                conn.commit()

            # Populate legacy bulk_store for tests
            bulk_store.store_batch(job_id, results, {"engine": "sync_fallback"})

            # Handle CSV export if requested
            if request.args.get("format") == "csv":
                from ..utils.io import dicts_to_csv

                return dicts_to_csv(results)

            return jsonify(
                {
                    "batch_id": job_id,
                    "status": "completed",  # Immediate completion
                    "results": results,
                    "total": len(domains),
                    "completed": len(domains),
                }
            )
        except Exception as e:
            logging.getLogger("techscan.bulk").exception("Synchronous bulk scan failed")
            return jsonify({"error": str(e)}), 500

    # Send to RQ
    try:
        q = _queue.get_queue()
        q.enqueue(_tasks.run_bulk_scan_task, job_id, domains, params, job_id=job_id, job_timeout=3600)
    except Exception as e:
        logging.getLogger("techscan").error(f"Failed to enqueue job {job_id}: {e}")
        # Update DB to failed
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scan_jobs SET status='failed', error=%s WHERE id=%s", (str(e), job_id))
            conn.commit()
        return jsonify({"error": "failed to start job"}), 500

    logging.getLogger("techscan.bulk").info("/bulk scan enqueued job=%s domains=%d", job_id, len(domains))
    return jsonify(
        {
            "batch_id": job_id,
            "job_id": job_id,
            "status": "pending",
            "message": "Scan started in background",
            "count": len(domains),
        }
    ), 202


@bp.route("/scan/cancelled", methods=["POST"])
def scan_cancelled():
    data = request.get_json(silent=True) or {}
    domain = str(data.get("domain") or "").strip()
    token = str(data.get("token") or "").strip()
    tokens = data.get("tokens") or []
    if isinstance(tokens, str):
        tokens = [tokens]
    cleaned_tokens = []
    if token:
        cleaned_tokens.append(token)
    for tok in tokens:
        if not tok:
            continue
        st = str(tok).strip()
        if st and st not in cleaned_tokens:
            cleaned_tokens.append(st)
    if cleaned_tokens:
        _register_cancel_tokens(cleaned_tokens)
    reason = data.get("reason") or "client_cancel"
    logger = logging.getLogger("techscan.scan")
    if domain:
        logger.info("single cancel acknowledged domain=%s reason=%s tokens=%d", domain, reason, len(cleaned_tokens))
    elif cleaned_tokens:
        logger.info("single cancel acknowledged reason=%s tokens=%d", reason, len(cleaned_tokens))
    return jsonify({"status": "ok", "logged_tokens": len(cleaned_tokens)})


@bp.route("/bulk/cancelled", methods=["POST"])
def bulk_cancelled():
    data = request.get_json(silent=True) or {}
    domains = data.get("domains") or []
    reason = data.get("reason") or "client_cancel"
    if isinstance(domains, str):
        domains = [domains]
    if not isinstance(domains, list):
        return jsonify({"error": "domains must be a list"}), 400
    cleaned = []
    for dom in domains:
        if not dom:
            continue
        cleaned.append(str(dom).strip())
    tokens = data.get("tokens") or []
    if isinstance(tokens, str):
        tokens = [tokens]
    cleaned_tokens = []
    for tok in tokens:
        if not tok:
            continue
        st = str(tok).strip()
        if st:
            cleaned_tokens.append(st)
    if cleaned_tokens:
        _register_cancel_tokens(cleaned_tokens)
    logger = logging.getLogger("techscan.bulk")
    for dom in cleaned:
        logger.info("bulk cancel acknowledged domain=%s reason=%s", dom, reason)
    if cleaned_tokens:
        logger.info("bulk cancel tokens logged=%d reason=%s", len(cleaned_tokens), reason)
    return jsonify({"status": "ok", "logged": len(cleaned), "logged_tokens": len(cleaned_tokens)})


@bp.route("/export/csv", methods=["GET"])
def export_csv():
    """Export cached (non-expired) scan results as CSV.
    Query params:
      domains=comma,separated,list (optional filter)
      include_raw=1 (include raw JSON in a column) (optional)
    Columns: domain,timestamp,tech_count,technologies,categories,cached,duration,retries,engine[,raw]
    - technologies: pipe-separated 'Name (version)' entries
    - categories: pipe-separated category names
    """
    domains_param = request.args.get("domains")
    doms = [d.strip().lower() for d in domains_param.split(",")] if domains_param else None
    include_raw = request.args.get("include_raw") == "1"
    outdated_only = request.args.get("outdated_only") == "1"
    rows = snapshot_cache(doms)
    if outdated_only:
        # Filter rows having audit.outdated_count > 0
        filtered = []
        for r in rows:
            audit_meta = r.get("audit") or {}
            if audit_meta.get("outdated_count"):
                filtered.append(r)
        rows = filtered
    import csv, io

    output = io.StringIO()
    fieldnames = [
        "domain",
        "timestamp",
        "tech_count",
        "technologies",
        "categories",
        "cached",
        "duration",
        "retries",
        "engine",
        "outdated_count",
        "outdated_list",
    ]
    if include_raw:
        fieldnames.append("raw")
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        techs = r.get("technologies") or []
        tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get("version") else "") for t in techs]
        categories = sorted((r.get("categories") or {}).keys())
        audit_meta = r.get("audit") or {}
        outdated_items = audit_meta.get("outdated") or []
        outdated_list_str = " | ".join(
            f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items
        )
        row = {
            "domain": r.get("domain"),
            "timestamp": r.get("timestamp"),
            "tech_count": len(techs),
            "technologies": " | ".join(tech_list),
            "categories": " | ".join(categories),
            "cached": r.get("cached", False),
            "duration": r.get("duration"),
            "retries": r.get("retries", 0),
            "engine": r.get("engine"),
            "outdated_count": audit_meta.get("outdated_count"),
            "outdated_list": outdated_list_str,
        }
        if include_raw:
            import json as _json

            row["raw"] = _json.dumps(r.get("raw"), ensure_ascii=False)
        writer.writerow(row)
    csv_data = output.getvalue()
    return Response(
        csv_data, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=techscan_export.csv"}
    )


# ============ Async Scan Endpoints ============


@bp.route("/scan/async", methods=["POST"])
def scan_async():
    """Submit scan job that runs in background.

    Returns job_id immediately. Client can poll /api/job/<id> for status.
    This allows scan to continue even if user navigates away.
    """
    from ..job_queue import get_job_queue
    from ..scan_utils import scan_unified

    data = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain", "").strip().lower()

    if not domain:
        return jsonify({"error": "domain required"}), 400

    # Validate domain
    host = extract_host(domain)
    if not host or not DOMAIN_RE.match(host):
        return jsonify({"error": "Invalid domain format"}), 400

    # Initialize job queue with scan function
    jq = get_job_queue()
    # Always set scan function to ensure correct budget_ms
    wapp_path = current_app.config["WAPPALYZER_PATH"]
    jq._scan_fn = lambda d, wpath=wapp_path, **opts: scan_unified(d, wpath, budget_ms=45000)
    if not jq._started:
        jq.start_worker()

    # Submit job
    options = {}
    if data.get("quick"):
        options["quick"] = True
    if data.get("deep"):
        options["deep"] = True

    job_id = jq.submit_single(domain, options)

    return jsonify(
        {
            "job_id": job_id,
            "status": "pending",
            "domain": domain,
            "message": "Scan submitted. Poll /api/job/<id> for status.",
        }
    )


@bp.route("/bulk/async", methods=["POST"])
def bulk_async():
    """Submit bulk scan job that runs in background.

    Returns job_id immediately. Client can poll /api/job/<id> for status.
    """
    from ..job_queue import get_job_queue
    from ..scan_utils import scan_unified

    data = request.get_json(force=True, silent=True) or {}
    domains = data.get("domains", [])

    if not domains:
        return jsonify({"error": "domains array required"}), 400

    if not isinstance(domains, list):
        return jsonify({"error": "domains must be array"}), 400

    # Clean and validate domains
    clean_domains = []
    for d in domains:
        if not isinstance(d, str):
            continue
        host = extract_host(d.strip().lower())
        if host and DOMAIN_RE.match(host):
            clean_domains.append(host)

    if not clean_domains:
        return jsonify({"error": "No valid domains provided"}), 400

    # Initialize job queue
    jq = get_job_queue()
    # Always set scan function to ensure correct budget_ms
    wapp_path = current_app.config["WAPPALYZER_PATH"]
    jq._scan_fn = lambda d, wpath=wapp_path, **opts: scan_unified(d, wpath, budget_ms=45000)
    if not jq._started:
        jq.start_worker()

    # Submit bulk job
    job_id = jq.submit_bulk(clean_domains)

    return jsonify(
        {
            "job_id": job_id,
            "status": "pending",
            "total": len(clean_domains),
            "message": "Bulk scan submitted. Poll /api/job/<id> for status.",
        }
    )


@bp.route("/api/job/<job_id>", methods=["GET"])
def get_job_status(job_id: str):
    """Get status of a scan job.

    Returns current status, progress, and result when completed.
    """
    from ..job_queue import get_job_queue
    import json

    if not job_id:
        return jsonify({"error": "job_id required"}), 400

    jq = get_job_queue()
    job = jq.get_job(job_id)

    if not job:
        return jsonify({"error": "Job not found", "job_id": job_id}), 404

    # Parse domains for response
    domains = []
    try:
        domains = json.loads(job.get("domains", "[]"))
    except:
        pass

    response = {
        "job_id": job.get("id"),
        "type": job.get("type"),
        "status": job.get("status"),
        "progress": job.get("progress", 0),
        "total": job.get("total", 1),
        "completed": job.get("completed", 0),
        "domains": domains[:10] if len(domains) > 10 else domains,  # limit response size
        "domains_count": len(domains),
        "error": job.get("error"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "finished_at": job.get("finished_at"),
    }

    # Include result for single completed jobs
    if job.get("status") == "completed" and job.get("type") == "single":
        if job.get("result"):
            try:
                response["result"] = json.loads(job.get("result"))
            except:
                response["result"] = job.get("result")

    # Include results summary for bulk completed jobs
    if job.get("status") == "completed" and job.get("type") == "bulk":
        if job.get("results"):
            try:
                response["results"] = json.loads(job.get("results"))
            except:
                pass

    return jsonify(response)


@bp.route("/api/jobs", methods=["GET"])
def list_jobs():
    """List recent scan jobs."""
    from ..job_queue import get_job_queue

    limit = request.args.get("limit", 20, type=int)
    limit = max(1, min(limit, 100))

    jq = get_job_queue()
    jobs = jq.get_recent_jobs(limit=limit)

    # Simplify response
    return jsonify(
        {
            "jobs": [
                {
                    "job_id": j.get("id"),
                    "type": j.get("type"),
                    "status": j.get("status"),
                    "progress": j.get("progress", 0),
                    "total": j.get("total", 1),
                    "completed": j.get("completed", 0),
                    "error": j.get("error"),
                    "created_at": j.get("created_at"),
                    "updated_at": j.get("updated_at"),
                }
                for j in jobs
            ],
            "count": len(jobs),
        }
    )
