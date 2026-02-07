from fastapi import APIRouter
import sqlite3

router = APIRouter()

DB_PATH = "scamdekho.db"


def query(sql):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql)
    data = cur.fetchall()
    conn.close()
    return data


@router.get("/stats")
def stats():

    total = query("SELECT COUNT(*) FROM scans")[0][0]

    scam = query("SELECT COUNT(*) FROM scans WHERE verdict='SCAM'")[0][0]

    safe = query("SELECT COUNT(*) FROM scans WHERE verdict='SAFE'")[0][0]

    text = query("SELECT COUNT(*) FROM scans WHERE type='text'")[0][0]

    image = query("SELECT COUNT(*) FROM scans WHERE type='image'")[0][0]

    url = query("SELECT COUNT(*) FROM scans WHERE type='url'")[0][0]

    recent = query("""
        SELECT type, content, verdict, created_at
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """)

    return {
        "total": total,
        "scam": scam,
        "safe": safe,
        "text": text,
        "image": image,
        "url": url,
        "recent": recent
    }
