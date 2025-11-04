import os, sys, types
os.environ['TECHSCAN_DISABLE_DB']='1'
os.environ['TECHSCAN_DISABLE_PERSIST_AUTOSTART']='1'
os.environ['TECHSCAN_SKIP_VERSION_AUDIT']='1'
import app.scan_utils as su
# monkeypatch scan_domain
def fake_scan_domain(domain, wappalyzer_path=None, timeout=None, retries=0, full=False):
    return {
        'domain': domain,
        'technologies': [
            {'name': 'Apache', 'version': '2.4.41', 'categories': ['Web servers'], 'confidence': 50}
        ],
        'categories': {'Web servers': [{'name': 'Apache', 'version': '2.4.41'}]}
    }
su.scan_domain = fake_scan_domain
# fake wapp_local
fake_wapp = types.SimpleNamespace()
def fake_detect(domain, wappalyzer_path=None, timeout=None):
    return {
        'technologies': [
            {'name': 'Apache', 'version': '2.4.41', 'categories': ['Web servers'], 'confidence': 50}
        ],
        'raw': {'extras': {'network': ['https://cdn.com/jquery.min.js']}},
        'data': {'extras': {'scripts': ['https://cdn.com/bootstrap.js']}}
    }
fake_wapp.detect = fake_detect
sys.modules['app.wapp_local'] = fake_wapp
print('Calling scan_unified...')
out = su.scan_unified('example.com', wappalyzer_path='does-not-exist', budget_ms=2000)
print('Returned technologies:', [t.get('name') for t in out.get('technologies', [])])
print('Returned out keys:', list(out.keys()))
print('nres in locals of module (if any):', hasattr(su, 'nres'))
