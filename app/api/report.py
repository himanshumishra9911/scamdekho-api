from fastapi import APIRouter
from pydantic import BaseModel
import sqlite3
from datetime import datetime

router = APIRouter()

class Report(BaseModel):
    name: str
    email: str
    scam_type: str
    description: str

@router.post("/")
def submit_report(report: Report):
    conn = sqlite3.connect("scamdekho.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scam_reports (name, email, scam_type, description, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        report.name,
        report.email,
        report.scam_type,
        report.description,
        datetime.now()
    ))

    conn.commit()
    conn.close()

    return {"message": "Report submitted successfully"}
