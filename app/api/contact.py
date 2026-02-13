from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
import ssl
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


class ContactRequest(BaseModel):
    name: str
    email: str
    message: str


@router.post("/")
def submit_contact(data: ContactRequest):

    if not EMAIL_USER or not EMAIL_PASS:
        raise HTTPException(status_code=500, detail="Email credentials missing")

    subject = f"New Contact from {data.name}"

    body = f"""
New Contact Message from ScamDekho

Name: {data.name}
Email: {data.email}

Message:
{data.message}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_USER

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL("smtp.zoho.in", 465, context=context, timeout=20) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, EMAIL_USER, msg.as_string())

        return {"message": "Email sent successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
