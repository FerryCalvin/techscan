import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Debug/reloader off by default to prevent double process & mid-scan restarts.
    # Enable by setting: (PowerShell) $env:TECHSCAN_DEBUG_SERVER='1'
    debug_flag = os.environ.get('TECHSCAN_DEBUG_SERVER', '0') == '1'
    # Even if debug_flag True, you can still disable auto reloader explicitly:
    use_reloader = debug_flag  # set False to completely suppress reloader
    # Print route map (non-verbose) so user can verify UI endpoints are present.
    try:
        routes = sorted({r.rule for r in app.url_map.iter_rules()})
        sample = routes[:20]
        print(f"[techscan] Route count={len(routes)} sample={sample}")
    except Exception as e:
        print(f"[techscan] Failed listing routes: {e}")
    app.run(host='0.0.0.0', port=5000, debug=debug_flag, use_reloader=use_reloader)
