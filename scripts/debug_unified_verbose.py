import sys, types, json, logging
from app import scan_utils

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('techscan.unified').setLevel(logging.DEBUG)

# prepare fake detector
dummy_raw = {"extras": {"network": ["https://cdn.com/jquery.min.js"]}}
fake = types.SimpleNamespace()
fake.detect = lambda domain, wappalyzer_path=None, timeout=None: {"raw": dummy_raw, "technologies": []}
# inject
sys.modules['app.wapp_local'] = fake
# monkeypatch load_categories
scan_utils.load_categories = lambda path: {}

res = scan_utils.scan_unified('example.com', wappalyzer_path='wappalyzer', budget_ms=1000)
print('RESULT TECHNOLOGIES:', [t.get('name') for t in res.get('technologies', [])])
print('RAW IN RESULT:', json.dumps(res.get('raw',{}), indent=2))
