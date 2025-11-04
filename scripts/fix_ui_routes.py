import re
p = r"d:/magang/techscan/app/routes/ui.py"
with open(p, 'r', encoding='utf-8') as f:
    s = f.read()
old = re.compile(r"@ui_bp\.route\('/'\)\s*@ui_bp\.route\('/dashboard'\)\s*def home\([\s\S]*?return render_template\('stats.html'\)\s*\n", re.M)
new = "@ui_bp.route('/')\ndef home():\n    # Restore previous behavior: root path serves the scanner page.\n    # The dashboard remains available at /dashboard and /stats.\n    return render_template('scanner.html')\n\n\n@ui_bp.route('/dashboard')\ndef dashboard_page():\n    # Explicit dashboard route (keeps compatibility with bookmarks)\n    return render_template('stats.html')\n\n"
if old.search(s):
    s2 = old.sub(new, s, count=1)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(s2)
    print('updated')
else:
    print('pattern not found')
