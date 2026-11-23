"""Export synthetic aggregates for a DataLens file connection and local demo."""
import csv
from pathlib import Path
from sqlalchemy import text
from app import app, db

query = """SELECT r.day, m.kind, r.status, count(*) AS orders,
sum(r.hours) AS rental_hours, sum(r.km) AS distance_one_way,
sum(r.delivery) AS delivery_sum, sum(r.total) AS quote_sum
FROM rental r JOIN machine m ON m.id=r.machine_id
WHERE r.user_id='10000000-0000-4000-8000-000000000001'
GROUP BY r.day, m.kind, r.status ORDER BY r.day, m.kind, r.status"""
with app.app_context():
    result = db.session.execute(text(query))
    header = list(result.keys())
    rows = list(result)
    assert sum(row.orders for row in rows) == 5000
with open("datalens.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(rows)
import json
template = Path("dashboard.template.html").read_text(encoding="utf-8")
payload = json.dumps([[str(row[0]), row[1], row[2], row[3], float(row[6]), float(row[7])] for row in rows])
Path("dashboard.html").write_text(template.replace("__ROWS__", payload), encoding="utf-8")
