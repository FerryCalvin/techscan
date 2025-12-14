import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db

app = create_app()
with db.get_conn() as conn:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT jsonb_array_length(technologies_json), technologies_json
            FROM scans
            WHERE domain=%s
            ORDER BY finished_at DESC
            LIMIT 1
            """,
            ('unair.ac.id',)
        )
        row = cur.fetchone()
        if not row:
            print('no rows')
        else:
            print('tech_count', row[0])
            print('json excerpt', str(row[1])[:400])
