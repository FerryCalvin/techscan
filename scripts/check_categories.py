#!/usr/bin/env python3
"""Check available categories from API."""
import urllib.request
import json

try:
    r = urllib.request.urlopen('http://localhost:5000/api/stats', timeout=10)
    d = json.loads(r.read())
    
    print("=== CATEGORIES FROM API ===")
    cats = d.get('categories', [])
    for c in sorted(cats, key=lambda x: x.get('count', 0), reverse=True):
        name = c.get('category', c.get('rawCategory', 'Unknown'))
        count = c.get('count', 0)
        print(f"  {name}: {count}")
    
    print(f"\nTotal categories: {len(cats)}")
    
    # Check specific categories
    print("\n=== CHECKING SPECIFIC CATEGORIES ===")
    test_cats = [
        'reverse proxies', 
        'ssl/tls certificate authorities',
        'operating systems',
        'security',
        'databases',
        'web frameworks'
    ]
    
    for cat in test_cats:
        try:
            url = f'http://localhost:5000/api/category/{urllib.parse.quote(cat)}/technologies'
            r2 = urllib.request.urlopen(url, timeout=10)
            d2 = json.loads(r2.read())
            techs = d2.get('technologies', [])
            print(f"  {cat}: {len(techs)} technologies")
            if techs:
                for t in techs[:3]:
                    print(f"    - {t.get('tech')}: {t.get('count')}")
        except Exception as e:
            print(f"  {cat}: ERROR - {e}")
            
except Exception as e:
    print(f"Error: {e}")
