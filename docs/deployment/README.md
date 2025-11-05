# Deployment examples

These are optional, production-oriented examples to help operators run TechScan reliably.
They’re templates: adapt paths, users, and domains to your environment.

## systemd + Gunicorn

1. Place your app at `/opt/techscan` (or a path you prefer), create venv, install deps:

```bash
python3 -m venv /opt/techscan/venv
/opt/techscan/venv/bin/pip install -r /opt/techscan/requirements.txt
```

2. Create env file for secrets, e.g. `/etc/techscan/techscan.env` (chmod 600):

```bash
TECHSCAN_DB_URL=postgresql://user:pass@db:5432/techscan
TECHSCAN_ADMIN_TOKEN=change-me
TECHSCAN_REDIS_URL=redis://localhost:6379/0
# Optional: WAPPALYZER_PATH if not auto-detected
# WAPPALYZER_PATH=/opt/techscan/node_scanner
```

3. Install systemd unit:

- Copy `systemd-techscan.service` to `/etc/systemd/system/techscan.service`
- Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now techscan
sudo systemctl status techscan
```

## Nginx reverse proxy

- Copy `nginx-techscan.conf` to `/etc/nginx/sites-available/techscan.conf`
- Symlink to `sites-enabled`, test, and reload:

```bash
sudo ln -s /etc/nginx/sites-available/techscan.conf /etc/nginx/sites-enabled/techscan.conf
sudo nginx -t
sudo systemctl reload nginx
```

Add TLS (Let's Encrypt or your provider) and redirect `http -> https` as appropriate.

## Notes

- Keep `.env` files out of git; prefer systemd EnvironmentFile or container secrets.
- For sustained throughput, set `TECHSCAN_REDIS_URL` for rate limiting.
- Scale Gunicorn workers/threads based on CPU and workload. Start with workers = cores*2 and tune.
- Set proper ulimit/LimitNOFILE if handling many concurrent sockets.
