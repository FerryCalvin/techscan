import csv
import io
from typing import List, Dict, Any
from flask import Response


def dicts_to_csv(data: List[Dict[str, Any]], filename: str = "export.csv") -> Response:
    """Convert a list of dictionaries to a CSV flask response."""
    if not data:
        return Response("", mimetype="text/csv")

    # Determine all keys (superset)
    keys = set()
    for item in data:
        keys.update(item.keys())

    # Sort keys for consistent output, prioritizing domain, status
    priority = ["status", "domain", "engine", "error"]
    sorted_keys = [k for k in priority if k in keys] + sorted([k for k in keys if k not in priority])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=sorted_keys)
    writer.writeheader()
    writer.writerows(data)

    return Response(
        output.getvalue(), mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"}
    )
