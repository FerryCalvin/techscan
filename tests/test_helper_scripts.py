import json, os, subprocess, sys, tempfile
from pathlib import Path
import unittest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / 'scripts'
FILTER = SCRIPTS_DIR / 'filter_need_deep.py'
MERGE = SCRIPTS_DIR / 'merge_deep_prefer.py'

PYTHON = sys.executable

def run(cmd, input=None):
    result = subprocess.run(cmd, input=input, text=True, capture_output=True)
    if result.returncode != 0:
        raise AssertionError(f"Command failed {cmd}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    return result.stdout

class TestHelperScripts(unittest.TestCase):
    def test_filter_need_deep_basic(self):
        data = [
            {"type":"meta","count":3},
            {"status":"ok","domain":"a.com","engine":"heuristic-tier0","technologies":[{"name":"WordPress"}]},
            {"status":"ok","domain":"b.com","engine":"heuristic-tier0","technologies":[{"name":"Nginx","version":"1.2.3"},{"name":"jQuery"}]},
            {"status":"ok","domain":"c.com","engine":"heuristic-tier0","technologies":[]},
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'quick.jsonl'
            p.write_text('\n'.join(json.dumps(o) for o in data))
            out = run([PYTHON, str(FILTER), str(p)])
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            self.assertIn('a.com', lines)
            self.assertIn('c.com', lines)
            self.assertNotIn('b.com', lines)

    def test_filter_require_version_mode(self):
        data = [
            {"status":"ok","domain":"x.com","engine":"heuristic-tier0","technologies":[{"name":"Lib","version":"0.1"}]},
            {"status":"ok","domain":"y.com","engine":"heuristic-tier0","technologies":[{"name":"Lib"},{"name":"Other"}]},
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'q.jsonl'
            p.write_text('\n'.join(json.dumps(o) for o in data))
            out = run([PYTHON, str(FILTER), str(p), '--require-version'])
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            self.assertIn('y.com', lines)
            self.assertNotIn('x.com', lines)

    def test_merge_prefers_deep(self):
        quick=[{"type":"meta"},{"status":"ok","domain":"a.com","engine":"heuristic-tier0","technologies":[{"name":"WordPress"}]},{"status":"ok","domain":"b.com","engine":"heuristic-tier0","technologies":[{"name":"Nginx"}]}]
        deep=[{"type":"meta"},{"status":"ok","domain":"b.com","engine":"deep-combined","technologies":[{"name":"Nginx","version":"1.25"}]},{"status":"ok","domain":"c.com","engine":"deep-combined","technologies":[{"name":"Apache"}]}]
        with tempfile.TemporaryDirectory() as td:
            q=Path(td)/'quick.jsonl'; d=Path(td)/'deep.jsonl'
            q.write_text('\n'.join(json.dumps(o) for o in quick))
            d.write_text('\n'.join(json.dumps(o) for o in deep))
            out = run([PYTHON, str(MERGE), str(q), str(d)])
            lines = [json.loads(l) for l in out.splitlines() if l.strip()]
            by_dom={}
            for o in lines[1:]:
                by_dom[o['domain']]=o
            self.assertIn('a.com', by_dom)
            self.assertTrue(by_dom['b.com']['engine'].startswith('deep'))
            self.assertTrue(any(t.get('version')=='1.25' for t in by_dom['b.com']['technologies']))
            self.assertIn('c.com', by_dom)

    def test_merge_ignores_error_if_success_exists(self):
        quick=[{"type":"meta"},{"status":"error","domain":"a.com","error":"timeout"}]
        deep=[{"type":"meta"},{"status":"ok","domain":"a.com","engine":"deep-combined","technologies":[]}]
        with tempfile.TemporaryDirectory() as td:
            q=Path(td)/'quick.jsonl'; d=Path(td)/'deep.jsonl'
            q.write_text('\n'.join(json.dumps(o) for o in quick))
            d.write_text('\n'.join(json.dumps(o) for o in deep))
            out=run([PYTHON, str(MERGE), str(q), str(d)])
            lines=[json.loads(l) for l in out.splitlines() if l.strip()]
            self.assertTrue(any(o.get('status')=='ok' and o.get('domain')=='a.com' for o in lines))
            self.assertFalse(any(o.get('status')=='error' and o.get('domain')=='a.com' for o in lines))

if __name__=='__main__':
    unittest.main()
