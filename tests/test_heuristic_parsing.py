import unittest, re, pathlib, sys

# Ensure module import path
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.heuristic_fast import parse_server_header, extract_x_powered_by, DB_PANEL_PATTERNS

class TestHeuristicParsing(unittest.TestCase):
    def test_parse_server_header_basic(self):
        self.assertEqual(parse_server_header('nginx/1.22.1'), ('Nginx','1.22.1'))
        self.assertEqual(parse_server_header('Apache'), ('Apache', None))
        self.assertEqual(parse_server_header('cloudflare'), ('Cloudflare', None))
        self.assertEqual(parse_server_header('LiteSpeed'), ('LiteSpeed', None))
        self.assertEqual(parse_server_header('openlitespeed/1.7.19'), ('LiteSpeed','1.7.19'))
        self.assertEqual(parse_server_header('openresty/1.21.4.1'), ('OpenResty','1.21.4.1'))
        self.assertEqual(parse_server_header('caddy'), ('Caddy', None))
        self.assertEqual(parse_server_header('gunicorn/20.1.0'), ('Gunicorn','20.1.0'))
        self.assertEqual(parse_server_header('uwsgi'), ('uWSGI', None))
        self.assertEqual(parse_server_header('varnish'), ('Varnish', None))
        self.assertEqual(parse_server_header('fastly'), ('Fastly', None))

    def test_parse_server_header_unmatched(self):
        # Unknown returns raw name
        self.assertEqual(parse_server_header('weirdserverX/2.3'), ('weirdserverX','2.3'))
        self.assertEqual(parse_server_header(''), (None, None))

    def test_extract_x_powered_by(self):
        hdr = 'PHP/8.2.12; Express/4.18.2, ASP.NET'
        items = extract_x_powered_by(hdr)
        self.assertIn(('PHP','8.2.12'), items)
        self.assertIn(('Express','4.18.2'), items)
        self.assertIn(('ASP.NET', None), items)

    def test_db_panel_patterns(self):
        html = '<html><body>Welcome to phpMyAdmin 5.2 – manage your MySQL database</body></html>'
        matches = [name for name, pat in DB_PANEL_PATTERNS if pat.search(html)]
        self.assertIn('phpMyAdmin', matches)
        adminer_html = '<h1>Adminer 4.8.1</h1>'
        matches2 = [name for name, pat in DB_PANEL_PATTERNS if pat.search(adminer_html)]
        self.assertIn('Adminer', matches2)

if __name__ == '__main__':
    unittest.main()
