from __future__ import annotations

import re
from typing import Any, Iterable, Tuple

_PLACEHOLDER_PATTERN = '(?:)'


def infer_snippet(url: str | None) -> str | None:
    if not url or not isinstance(url, str):
        return None
    clean = url.split('#', 1)[0]
    lowered = clean.lower()
    if lowered.endswith(('.css', '.css?')) or '.css?' in lowered:
        return f'<link rel="stylesheet" href="{clean}">'  # noqa: E501
    if lowered.endswith(('.js', '.js?')) or '.js?' in lowered:
        return f'<script src="{clean}" defer></script>'
    if any(lowered.endswith(ext) for ext in ('.woff2', '.woff', '.ttf', '.otf', '.eot')) or any(ext in lowered for ext in ('.woff2?', '.woff?', '.ttf?', '.otf?', '.eot?')):
        ext = lowered.rsplit('.', 1)[-1].split('?', 1)[0]
        font_mime = {
            'woff2': 'font/woff2',
            'woff': 'font/woff',
            'ttf': 'font/ttf',
            'otf': 'font/otf',
            'eot': 'application/vnd.ms-fontobject'
        }
        mime = font_mime.get(ext, 'font/woff2')
        return f'<link rel="preload" href="{clean}" as="font" type="{mime}" crossorigin>'
    return f'<link rel="preload" href="{clean}" as="fetch">'


def _is_placeholder_pattern(value: str | None) -> bool:
    if not value:
        return False
    return value.strip() == _PLACEHOLDER_PATTERN


def _normalise_confidence(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def normalize_evidence_entry(ev: dict) -> dict | None:
    if not isinstance(ev, dict):
        return None
    out: dict[str, Any] = {}
    kind = ev.get('kind') or ev.get('type') or 'pattern'
    out['kind'] = kind
    source = ev.get('source')
    if source:
        out['source'] = source
    pattern = ev.get('pattern') or ev.get('regex')
    if pattern and not _is_placeholder_pattern(pattern):
        out['pattern'] = pattern
    match = ev.get('match') or ev.get('value_match')
    if match:
        out['match'] = match
    value = ev.get('value')
    if value is not None:
        out['value'] = value
    confidence = _normalise_confidence(ev.get('confidence'))
    if confidence is not None:
        out['confidence'] = confidence
    version = ev.get('version')
    if version:
        out['version'] = version
    implies = ev.get('implies')
    if implies:
        out['implies'] = implies
    excludes = ev.get('excludes')
    if excludes:
        out['excludes'] = excludes
    url = ev.get('url')
    if not url and isinstance(value, str) and value.lower().startswith(('http://', 'https://')):
        url = value
    if url:
        out['url'] = url
        snippet = ev.get('snippet') or infer_snippet(url)
        if snippet:
            out['snippet'] = snippet
    elif ev.get('snippet'):
        out['snippet'] = ev.get('snippet')
    headers = ev.get('headers')
    if isinstance(headers, dict) and headers:
        out['headers'] = headers
    matches = ev.get('matches')
    if isinstance(matches, list) and matches:
        filtered = []
        for match_entry in matches:
            if not isinstance(match_entry, dict):
                continue
            entry_pattern = match_entry.get('pattern') or match_entry.get('regex')
            if _is_placeholder_pattern(entry_pattern):
                continue
            filtered.append(match_entry)
        if filtered:
            out['matches'] = filtered
    urls = ev.get('urls')
    if isinstance(urls, list) and urls:
        out['urls'] = urls
    note = ev.get('note') or ev.get('reason')
    if note:
        out['note'] = note
    key = ev.get('key')
    if key:
        out['key'] = key
    if not out:
        return None
    meaningful_keys = {'snippet','url','value','match','pattern','headers','matches','urls','note','key','implies','excludes','version'}
    if not any(k in out for k in meaningful_keys):
        return None
    return out


def pattern_to_evidence(entry: dict) -> dict | None:
    if not isinstance(entry, dict):
        return None
    pattern = entry.get('regex')
    if _is_placeholder_pattern(pattern):
        pattern = None
    ev: dict[str, Any] = {
        'kind': entry.get('type') or 'pattern',
        'source': entry.get('type'),
        'pattern': pattern,
        'match': entry.get('match'),
        'value': entry.get('value'),
        'confidence': _normalise_confidence(entry.get('confidence')),
        'version': entry.get('version'),
        'implies': entry.get('implies'),
        'excludes': entry.get('excludes')
    }
    value = entry.get('value')
    if isinstance(value, str) and value.lower().startswith(('http://', 'https://')):
        ev['url'] = value
        snippet = infer_snippet(value)
        if snippet:
            ev['snippet'] = snippet
    # Remove empty/null keys and placeholder pattern
    clean = {k: v for k, v in ev.items() if v not in (None, [], {}, '')}
    if not clean.get('pattern') and not clean.get('url') and not clean.get('match') and not clean.get('value'):
        return None
    return clean


def extras_fallback_evidence(tech_key: str, extras: dict) -> list[dict]:
    evidence: list[dict[str, Any]] = []
    if not isinstance(extras, dict):
        return evidence
    tech_lc = (tech_key or '').lower()
    scripts = extras.get('scripts') or []
    for s in scripts:
        if not isinstance(s, str):
            continue
        if tech_lc and tech_lc not in s.lower():
            continue
        entry: dict[str, Any] = {'kind': 'asset', 'source': 'extras.scripts', 'url': s}
        snippet = infer_snippet(s)
        if snippet:
            entry['snippet'] = snippet
        evidence.append(entry)
    metas = extras.get('meta') or {}
    if isinstance(metas, dict):
        for k, v in metas.items():
            kv = f'{k}:{v}'
            if tech_lc and tech_lc not in kv.lower():
                continue
            evidence.append({'kind': 'meta', 'source': 'extras.meta', 'key': k, 'value': v})
    globals_map = extras.get('globals') or {}
    if isinstance(globals_map, dict):
        for gk, gv in globals_map.items():
            gv_str = str(gv)
            if tech_lc and tech_lc not in gk.lower() and tech_lc not in gv_str.lower():
                continue
            evidence.append({'kind': 'global', 'source': 'extras.globals', 'key': gk, 'value': gv_str})
    return evidence


def _normalise_header_dict(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict):
        return {k: v for k, v in data.items()}
    if isinstance(data, list):
        out: dict[str, Any] = {}
        for item in data:
            if isinstance(item, dict):
                out.update(item)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                out[str(item[0])] = item[1]
        return out or None
    return None


def extract_header_maps(raw_blob: dict | None) -> list[Tuple[str, dict[str, Any]]]:
    if not isinstance(raw_blob, dict):
        return []

    header_maps: list[Tuple[str, dict[str, Any]]] = []

    def add(source: str, value: Any) -> None:
        normalised = _normalise_header_dict(value)
        if normalised:
            header_maps.append((source, normalised))

    add('headers', raw_blob.get('headers'))
    for key in ('response', 'primary_response', 'primaryResponse', 'request'):
        sub = raw_blob.get(key)
        if isinstance(sub, dict):
            add(f'{key}.headers', sub.get('headers'))
    responses = raw_blob.get('responses') or raw_blob.get('httpResponses')
    if isinstance(responses, list):
        for idx, resp in enumerate(responses):
            if isinstance(resp, dict):
                add(f'responses[{idx}].headers', resp.get('headers'))
    return header_maps


def collect_header_evidence(tech_key: str, header_maps: Iterable[Tuple[str, dict[str, Any]]], aliases: Iterable[str] | None = None) -> list[dict]:
    tech_tokens = _tokenise_names([tech_key] + list(aliases or []))
    if not tech_tokens:
        return []
    evidence: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source, headers in header_maps:
        if not isinstance(headers, dict):
            continue
        for key, raw_value in headers.items():
            if raw_value is None:
                continue
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                value_str = str(value)
                joined = f'{key}: {value_str}'
                lower_joined = joined.lower()
                if not any(token in lower_joined for token in tech_tokens):
                    continue
                dedup_key = (key.lower(), value_str.lower())
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                evidence.append({
                    'kind': 'header',
                    'source': f'header:{source}',
                    'key': key,
                    'value': value_str,
                    'pattern': key,
                    'match': value_str
                })
    return evidence


def _tokenise_names(names: Iterable[str | None]) -> set[str]:
    tokens: set[str] = set()
    for name in names:
        if not name:
            continue
        lowered = name.lower()
        tokens.add(lowered)
        tokens.add(re.sub(r'[^a-z0-9]+', '', lowered))
        tokens.add(lowered.replace(' ', ''))
    return {t for t in tokens if t}


def _hashable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((k, _hashable_value(v)) for k, v in value.items()))
    if isinstance(value, list):
        return tuple(_hashable_value(v) for v in value)
    return value


def dedupe_evidence_entries(items: Iterable[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[Any] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = tuple(sorted((k, _hashable_value(v)) for k, v in item.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def merge_evidence_sources(*sources: Iterable[dict]) -> list[dict]:
    merged: list[dict] = []
    for source in sources:
        if not source:
            continue
        for item in source:
            normalised = normalize_evidence_entry(item) if not isinstance(item, dict) or 'kind' not in item else normalize_evidence_entry(dict(item))
            if normalised:
                merged.append(normalised)
    return dedupe_evidence_entries(merged)
