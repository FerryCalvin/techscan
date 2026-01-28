from app import create_app

app = create_app()
routes = sorted({r.rule for r in app.url_map.iter_rules()})
print("Route count:", len(routes))
print("Has /stats:", "/stats" in routes)
print("Stats-like:", [r for r in routes if "stats" in r])
print("Sample:", routes[:40])
