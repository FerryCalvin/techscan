#!/usr/bin/env python3
"""Audit category classification by fetching data from API endpoints."""

import urllib.request
import json
import sys

BASE_URL = "http://localhost:5000"

# Categories to audit
CATEGORIES_TO_AUDIT = [
    "programming languages",
    "web servers", 
    "javascript libraries",
    "javascript frameworks",
    "javascript runtimes",
    "cdn",
    "ui frameworks",
    "css frameworks",
    "cms",
    "analytics",
    "uncategorized"
]

# Technologies that should NOT be in certain categories
WRONG_CATEGORY_MAPPINGS = {
    "programming languages": ["node.js", "typescript", "next.js", "nuxt.js", "express", "deno", "bun"],
    "web servers": ["node.js", "next.js", "nuxt.js", "express", "nuxt", "gatsby", "react", "vue.js", "angular"],
    "cdn": ["jquery", "jquery ui", "jquery migrate", "jquery cdn", "react", "vue.js", "bootstrap", "font awesome"],
}

# Technologies that SHOULD be in certain categories
CORRECT_CATEGORY_MAPPINGS = {
    "programming languages": ["php", "python", "ruby", "java", "go"],
    "web servers": ["nginx", "apache", "litespeed", "caddy", "iis", "apache http server"],
    "javascript libraries": ["jquery", "react", "vue.js", "moment.js", "lodash", "axios"],
    "javascript frameworks": ["angular", "next.js", "nuxt.js", "express", "gatsby", "ember.js"],
    "javascript runtimes": ["node.js", "deno", "bun"],
    "cdn": ["cloudflare", "jsdelivr", "cdnjs"],
    "ui frameworks": ["bootstrap", "foundation", "semantic ui"],
    "css frameworks": ["tailwind css", "bulma"],
}

def fetch_category(category_name):
    """Fetch technologies for a category from API."""
    try:
        url = f"{BASE_URL}/api/category/{urllib.parse.quote(category_name)}/technologies"
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e), "technologies": []}

def audit_category(category_name, data):
    """Audit a category for correct/incorrect technologies."""
    techs = data.get("technologies", [])
    tech_names = [t["tech"].lower() for t in techs]
    
    issues = []
    
    # Check for technologies that should NOT be here
    wrong_techs = WRONG_CATEGORY_MAPPINGS.get(category_name, [])
    found_wrong = [t for t in wrong_techs if t in tech_names]
    if found_wrong:
        issues.append(f"  ❌ WRONG: {', '.join(found_wrong)}")
    
    # Check for technologies that SHOULD be here
    correct_techs = CORRECT_CATEGORY_MAPPINGS.get(category_name, [])
    missing = [t for t in correct_techs if t not in tech_names]
    if missing:
        issues.append(f"  ⚠️ MISSING: {', '.join(missing)}")
    
    # List what's found
    found_correct = [t for t in correct_techs if t in tech_names]
    if found_correct:
        issues.append(f"  ✅ CORRECT: {', '.join(found_correct)}")
    
    return issues

def main():
    print("=" * 60)
    print("CATEGORY CLASSIFICATION AUDIT")
    print("=" * 60)
    
    import urllib.parse
    
    all_issues = []
    
    for category in CATEGORIES_TO_AUDIT:
        print(f"\n📂 {category.upper()}")
        print("-" * 40)
        
        data = fetch_category(category)
        
        if "error" in data and data["error"]:
            print(f"  ⚠️ Error: {data['error']}")
            continue
        
        techs = data.get("technologies", [])
        print(f"  Total: {len(techs)} technologies")
        
        # Show top 10
        top_techs = techs[:10]
        if top_techs:
            print("  Top 10:")
            for t in top_techs:
                print(f"    • {t['tech']}: {t['count']}")
        
        # Run audit
        issues = audit_category(category, data)
        for issue in issues:
            print(issue)
            if "WRONG" in issue:
                all_issues.append(f"{category}: {issue}")
    
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    
    if all_issues:
        print("\n❌ Issues found:")
        for issue in all_issues:
            print(f"  {issue}")
    else:
        print("\n✅ All categories look correct!")
    
    # Save detailed report to file
    with open("audit_report.txt", "w", encoding="utf-8") as f:
        f.write("CATEGORY AUDIT REPORT\n")
        f.write("=" * 60 + "\n\n")
        for category in CATEGORIES_TO_AUDIT:
            import urllib.parse
            data = fetch_category(category)
            techs = data.get("technologies", [])
            f.write(f"\n{category.upper()}\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total: {len(techs)}\n")
            for t in techs[:15]:
                f.write(f"  - {t['tech']}: {t['count']}\n")
            if len(techs) > 15:
                f.write(f"  ... and {len(techs) - 15} more\n")
        f.write("\n\nSUMMARY: " + ("Issues found" if all_issues else "All correct") + "\n")
    print("\nDetailed report saved to: audit_report.txt")
    
    return 0 if not all_issues else 1

if __name__ == "__main__":
    sys.exit(main())
