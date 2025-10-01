import unittest, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import version_audit

class TestVersionAudit(unittest.TestCase):
    def test_compare_versions(self):
        self.assertEqual(version_audit.compare_versions('1.2.3','1.2.4'), -1)
        self.assertEqual(version_audit.compare_versions('1.2.3','1.2.3'), 0)
        self.assertEqual(version_audit.compare_versions('1.3.0','1.2.9'), 1)
        # Non-semver treated as not-outdated
        self.assertEqual(version_audit.compare_versions('dev-build','1.2.0'), 1)

    def test_audit_outdated_and_latest(self):
        latest_map = {'React':'18.3.1','Vue.js':'3.5.8','jQuery':'3.7.1'}
        scan = {'technologies':[{'name':'React','version':'18.2.0'}, # minor behind
                                 {'name':'Vue.js','version':'3.5.8'}, # latest
                                 {'name':'jQuery','version':'2.2.4'}  # major behind
                                ]}
        out = version_audit.audit_versions(scan, latest_map)
        react = next(t for t in out['technologies'] if t['name']=='React')
        vue = next(t for t in out['technologies'] if t['name']=='Vue.js')
        jq = next(t for t in out['technologies'] if t['name']=='jQuery')
        self.assertEqual(react['audit']['status'],'outdated')
        self.assertEqual(react['audit']['latest'],'18.3.1')
        self.assertIn(react['audit']['difference'], ('minor','patch'))  # expect minor (major same, minor diff)
        self.assertEqual(vue['audit']['status'],'latest')
        self.assertEqual(jq['audit']['status'],'outdated')
        self.assertEqual(jq['audit']['difference'], 'major')
        self.assertIn('audit', out)
        self.assertGreaterEqual(out['audit']['outdated_count'], 1)
        # Root counts classification
        self.assertGreaterEqual(out['audit']['outdated_major'], 1)
        self.assertGreaterEqual(out['audit']['outdated_minor'] + out['audit']['outdated_patch'], 1)

    def test_audit_ignores_missing_version(self):
        latest_map = {'WordPress':'6.9.0'}
        scan = {'technologies':[{'name':'WordPress','version':None}]}
        out = version_audit.audit_versions(scan, latest_map)
        self.assertNotIn('audit', out)

if __name__ == '__main__':
    unittest.main()
