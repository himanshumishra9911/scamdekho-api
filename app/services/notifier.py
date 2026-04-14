import smtplib
import os
import traceback
from email.mime.text import MIMEText
from datetime import datetime

EMAIL_FROM     = os.environ.get("ALERT_EMAIL_FROM")
EMAIL_TO       = os.environ.get("ALERT_EMAIL_TO")
EMAIL_PASSWORD = os.environ.get("ALERT_EMAIL_PASSWORD")

def send_failure_alert(check_type: str, input_data: str, reason: str, extra: dict = {}):
    """
    check_type: "upi", "qr", "payment_screenshot", etc.
    input_data: jo user ne check kiya (UPI ID, phone, etc.)
    reason:     failure ka reason
    extra:      koi bhi additional info
    """
    try:
        body = f"""
🚨 ScamDekho Check Failed!

Type     : {check_type}
Input    : {input_data}
Reason   : {reason}
Time     : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Extra    : {extra}
        """.strip()

        msg = MIMEText(body)
        msg["Subject"] = f"[ScamDekho] ❌ {check_type} check failed — {input_data}"
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

        print(f"[Notifier] Alert sent for {check_type}: {input_data}")

    except Exception as e:
        print(f"[Notifier] Email send FAILED: {e}")
