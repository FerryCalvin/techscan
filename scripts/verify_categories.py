
import sys
import os
import re

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.utils.tech_data import infer_tech_from_urls
from app.heuristic_fast import CATEGORY_MAP, WP_PLUGIN_PATTERNS

def test_inference_categories():
    print("Testing infer_tech_from_urls categories...")
    urls = [
        "https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js",
        "https://fonts.googleapis.com/css?family=Roboto",
        "https://www.google-analytics.com/analytics.js"
    ]
    
    hints = infer_tech_from_urls(urls)
    
    expected = {
        'jQuery': 'JavaScript libraries',
        'Bootstrap': 'UI frameworks',
        'Google Font API': 'Font scripts',
        'Google Analytics': 'Analytics'
    }
    
    failures = []
    for hint in hints:
        name = hint['name']
        cats = hint.get('categories', [])
        print(f"  {name}: {cats}")
        
        if name in expected:
            if not cats:
                failures.append(f"{name} has no categories")
            elif expected[name] not in cats:
                failures.append(f"{name} missing expected category '{expected[name]}'. Got: {cats}")
                
    if failures:
        print("\nINFERENCE FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return False
    else:
        print("Inference categories PASS")
        return True

def test_heuristic_map_completeness():
    print("\nTesting heuristic CATEGORY_MAP completeness...")
    failures = []
    
    # Check WP Plugins
    for name, pat in WP_PLUGIN_PATTERNS:
        if name not in CATEGORY_MAP:
            failures.append(f"WP Plugin '{name}' missing from CATEGORY_MAP")
            
    if failures:
        print("\nHEURISTIC FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return False
    else:
        print("Heuristic map PASS")
        return True

if __name__ == "__main__":
    p1 = test_inference_categories()
    p2 = test_heuristic_map_completeness()
    
    if p1 and p2:
        print("\nALL CHECKS PASSED")
        sys.exit(0)
    else:
        print("\nSOME CHECKS FAILED")
        sys.exit(1)
