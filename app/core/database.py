import sqlite3
from datetime import datetime

conn = sqlite3.connect("scamdekho.db", check_same_thread=False)

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    content TEXT,
    verdict TEXT,
    risk_score INTEGER,
    created_at TEXT
)
""")

conn.commit()


def save_scan(scan_type, content, verdict, risk_score):

    cursor.execute("""
    INSERT INTO scans (type, content, verdict, risk_score, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        scan_type,
        content[:2000],  # limit size
        verdict,
        risk_score,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
