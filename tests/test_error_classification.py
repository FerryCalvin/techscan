import unittest, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.scan.network import classify_error


class DummyTimeout(Exception):
    pass


class TestErrorClassification(unittest.TestCase):
    def test_timeout(self):
        self.assertEqual(classify_error(DummyTimeout("Timeout waiting for navigation")), "timeout")

    def test_dns(self):
        self.assertEqual(classify_error(Exception("NXDOMAIN result")), "dns")

    def test_ssl(self):
        self.assertEqual(classify_error(Exception("SSL certificate error")), "ssl")

    def test_conn(self):
        self.assertEqual(classify_error(Exception("Connection refused by host")), "conn")

    def test_preflight(self):
        self.assertEqual(classify_error(Exception("preflight unreachable host")), "preflight")

    def test_quarantine(self):
        self.assertEqual(classify_error(Exception("domain in temporary quarantine")), "quarantine")

    def test_other(self):
        self.assertEqual(classify_error(Exception("weird unknown issue happened")), "other")


if __name__ == "__main__":
    unittest.main()
