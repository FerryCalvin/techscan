import sys, pathlib
from unittest import mock
import io
import csv

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app

SAMPLE_RESULTS = [
    {
        'status': 'ok',
        'domain': 'example.com',
        'timestamp': 111,
        'technologies': [{'name':'WordPress','version':'6.0','categories':['CMS']}],
        'categories': {'CMS': [{'name':'WordPress','version':'6.0'}]},
        'cached': False,
        'duration': 1.2,
        'retries': 0,
        'engine': 'fast',
        'audit': {'outdated_count': 0}
    },
    {
        'status': 'error',
        'domain': 'bad.com',
        'error': 'timeout'
    }
]

@mock.patch('app.routes.scan.scan_bulk')
@mock.patch('app.routes.scan.bulk_quick_then_deep')
def test_bulk_csv(mock_two_phase, mock_bulk):
    # Simulate standard bulk (non two-phase)
    mock_two_phase.return_value = []
    mock_bulk.return_value = SAMPLE_RESULTS
    app = create_app()
    client = app.test_client()
    payload = {'domains':['example.com','bad.com'], 'timeout':5, 'retries':0, 'concurrency':2, 'format':'csv'}
    r = client.post('/bulk?format=csv', json=payload)
    assert r.status_code == 200
    assert r.mimetype == 'text/csv'
    content = r.get_data(as_text=True)
    rows = list(csv.reader(io.StringIO(content)))
    assert rows[0][0] == 'status'
    # Should have two data rows
    assert any('example.com' in row for row in rows)
    assert any('bad.com' in row for row in rows)

@mock.patch('app.routes.scan.quick_single_scan')
@mock.patch('app.routes.scan.scan_bulk')
@mock.patch('app.routes.scan.bulk_quick_then_deep')
def test_bulk_fallback_quick(mock_two_phase, mock_bulk, mock_quick):
    mock_two_phase.return_value = []
    mock_bulk.return_value = [
        {'status':'ok','domain':'ok.com','technologies':[],'categories':{},'engine':'fast'},
        {'status':'error','domain':'timeout.com','error':'Timeout exceeded'}
    ]
    mock_quick.return_value = {
        'domain':'timeout.com','technologies':[], 'categories':{}, 'engine':'heuristic-quick', 'timestamp':123
    }
    app = create_app()
    client = app.test_client()
    r = client.post('/bulk?fallback_quick=1', json={'domains':['ok.com','timeout.com']})
    assert r.status_code == 200
    data = r.get_json()
    timeout_entry = [x for x in data['results'] if x['domain']=='timeout.com'][0]
    assert timeout_entry.get('fallback') == 'quick'
    assert timeout_entry.get('original_error')
