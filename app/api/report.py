from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import sqlite3
from datetime import datetime
import os

router = APIRouter()

DB_PATH = "scamdekho.db"

class Report(BaseModel):
    name: str
    email: str
    scam_type: str
    description: str


def init_db():
    """Create table if not exists"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            scam_type TEXT,
            description TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


@router.post("/")
def submit_report(report: Report):
    try:
        # Ensure DB + table exists
        init_db()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scam_reports 
            (name, email, scam_type, description, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            report.name,
            report.email,
            report.scam_type,
            report.description,
            datetime.utcnow().isoformat()
        ))

        conn.commit()
        conn.close()

        return {"message": "Report submitted successfully"}

    except Exception as e:
        print("Report Error:", str(e))
        raise HTTPException(status_code=500, detail="Failed to submit report")
