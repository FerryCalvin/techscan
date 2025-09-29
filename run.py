import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Debug/reloader off by default to prevent double process & mid-scan restarts.
    # Enable by setting: (PowerShell) $env:TECHSCAN_DEBUG_SERVER='1'
    debug_flag = os.environ.get('TECHSCAN_DEBUG_SERVER', '0') == '1'
    # Even if debug_flag True, you can still disable auto reloader explicitly:
    use_reloader = debug_flag  # set False to completely suppress reloader
    app.run(host='0.0.0.0', port=5000, debug=debug_flag, use_reloader=use_reloader)
