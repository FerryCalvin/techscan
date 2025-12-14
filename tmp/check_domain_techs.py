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
            SELECT tech_name, version, categories
            FROM domain_techs
            WHERE domain=%s
            ORDER BY tech_name
            """,
            ('unair.ac.id',)
        )
        rows = cur.fetchall()
        print('domain_techs rows', len(rows))
        for row in rows:
            print(row)
