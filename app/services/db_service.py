from app.core.database import db
from datetime import datetime


async def save_scan(scan_type, content, verdict, risk_score, extra: dict = None):
    doc = {
        "type": scan_type,
        "content": content[:2000],
        "verdict": verdict,
        "risk_score": risk_score,
        "created_at": datetime.utcnow()
    }
    if extra:
        doc.update(extra)
    await db.scam_checks.insert_one(doc)