"""Backfill tech_count and versions_count columns for existing scans rows.

Usage (environment must have TECHSCAN_DB_URL):
  python -m scripts.backfill_counts

This script scans existing rows where tech_count IS NULL (or versions_count IS NULL)
then recomputes counts from technologies_json.

Idempotent: safe to re-run; will only update rows needing backfill unless --force provided.

Optional flags:
  --force    Recompute for all rows (even those already having counts)
  --limit N  Process at most N rows (default 5000 per batch)
"""
from __future__ import annotations
import os, json, argparse, logging
import psycopg

# Require TECHSCAN_DB_URL from environment; do not ship default credentials.
try:
    DB_URL = os.environ['TECHSCAN_DB_URL']
except KeyError:
    raise RuntimeError('TECHSCAN_DB_URL is required for backfill_counts.py')

log = logging.getLogger('techscan.backfill')
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def backfill(limit: int, force: bool):
    with psycopg.connect(DB_URL, autocommit=False) as conn:
        with conn.cursor() as cur:
            if force:
                cur.execute('SELECT id, technologies_json FROM scans ORDER BY id')
            else:
                cur.execute('''SELECT id, technologies_json FROM scans
                               WHERE tech_count IS NULL OR versions_count IS NULL
                               ORDER BY id LIMIT %s''', (limit,))
            rows = cur.fetchall()
            if not rows:
                log.info('No rows need backfill.')
                return 0
            updated = 0
            for sid, tech_json in rows:
                try:
                    techs = tech_json if isinstance(tech_json, list) else []
                except Exception:
                    techs = []
                tech_count = len(techs)
                versions_count = sum(1 for t in techs if isinstance(t, dict) and t.get('version'))
                cur.execute('UPDATE scans SET tech_count=%s, versions_count=%s WHERE id=%s', (tech_count, versions_count, sid))
                updated += 1
            conn.commit()
            log.info('Updated %s rows', updated)
            return updated

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=5000)
    ap.add_argument('--force', action='store_true')
    args = ap.parse_args()
    total = 0
    updated = backfill(args.limit, args.force)
    total += updated
    log.info('Backfill complete updated=%s', total)

if __name__ == '__main__':
    main()
