import requests, json, sys
url = 'http://127.0.0.1:5000/api/stats'
try:
    r = requests.get(url, timeout=5)
    print('HTTP', r.status_code)
    try:
        j = r.json()
        print('KEYS:', list(j.keys()))
        tt = j.get('top_technologies')
        tc = j.get('top_categories')
        print('top_technologies:', 'None' if tt is None else f'len={len(tt)}')
        if isinstance(tt, list):
            print('first 3 top_technologies:', json.dumps(tt[:3], indent=2)[:1000])
        print('top_categories:', 'None' if tc is None else f'len={len(tc)}')
        if isinstance(tc, list):
            print('first 5 top_categories:', json.dumps(tc[:5], indent=2)[:1000])
    except Exception as e:
        print('JSON parse failed', e)
except Exception as e:
    print('Request failed:', e)
    sys.exit(2)
