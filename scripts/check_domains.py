#!/usr/bin/env python3
"""Check how domains with paths are stored in database - standalone version."""
import os
import psycopg

# DB connection from env
db_host = os.environ.get('TECHSCAN_DB_HOST', '127.0.0.1')
db_port = os.environ.get('TECHSCAN_DB_PORT', '5432')
db_name = os.environ.get('TECHSCAN_DB_NAME', 'techscan')
db_user = os.environ.get('TECHSCAN_DB_USER', 'postgres')
db_pass = os.environ.get('TECHSCAN_DB_PASSWORD', '')

DB_URL = f'postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}'

try:
    with psycopg.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            # Check scans table for fkg.unair.ac.id
            cur.execute("""
                SELECT DISTINCT domain 
                FROM scans 
                WHERE domain LIKE '%fkg.unair%'
                ORDER BY domain
            """)
            rows = cur.fetchall()
            print("=== SCANS TABLE ===")
            print(f"Total distinct domains matching 'fkg.unair': {len(rows)}")
            for r in rows:
                print(f"  {r[0]}")
            
            # Check domain_techs table
            cur.execute("""
                SELECT DISTINCT domain 
                FROM domain_techs 
                WHERE domain LIKE '%fkg.unair%'
                ORDER BY domain
            """)
            rows2 = cur.fetchall()
            print("\n=== DOMAIN_TECHS TABLE ===")
            print(f"Total distinct domains matching 'fkg.unair': {len(rows2)}")
            for r in rows2:
                print(f"  {r[0]}")
                
            # Total domains in database
            cur.execute("SELECT COUNT(DISTINCT domain) FROM scans")
            total_scans = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT domain) FROM domain_techs")
            total_dt = cur.fetchone()[0]
            print(f"\n=== TOTALS ===")
            print(f"Total distinct domains in scans: {total_scans}")
            print(f"Total distinct domains in domain_techs: {total_dt}")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
