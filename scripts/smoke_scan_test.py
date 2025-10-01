import os, json, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.scan_utils import quick_single_scan, deep_scan

os.environ.setdefault('TECHSCAN_VERSION_ENRICH','0')

def main():
    domains=['example.com']
    for dom in domains:
        try:
            q = quick_single_scan(dom, os.environ.get('WAPPALYZER_PATH',''))
            print('quick_single_scan', dom, 'engine=', q.get('engine'), 'tech=', len(q.get('technologies',[])))
        except Exception as e:
            print('quick_single_scan FAILED', dom, e)
        try:
            d = deep_scan(dom, os.environ.get('WAPPALYZER_PATH',''))
            print('deep_scan', dom, 'engine=', d.get('engine'), 'tech=', len(d.get('technologies',[])))
        except Exception as e:
            print('deep_scan FAILED', dom, e)

if __name__=='__main__':
    main()
