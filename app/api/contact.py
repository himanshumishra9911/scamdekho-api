from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
import os

router = APIRouter()

RESEND_API_KEY = os.getenv("RESEND_API_KEY")

class ContactRequest(BaseModel):
    name: str
    email: str
    message: str

@router.post("/")
def submit_contact(data: ContactRequest):

    if not RESEND_API_KEY:
        raise HTTPException(status_code=500, detail="Resend API key missing")

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": "ScamDekho <noreply@send.scamdekho.in>",
            "to": ["contact@scamdekho.in"],
            "subject": f"New Contact from {data.name}",
            "html": f"""
                <h3>New Contact Message</h3>
                <p><strong>Name:</strong> {data.name}</p>
                <p><strong>Email:</strong> {data.email}</p>
                <p><strong>Message:</strong><br>{data.message}</p>
            """,
        },
    )

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=response.text)

    return {"message": "Email sent successfully"}
