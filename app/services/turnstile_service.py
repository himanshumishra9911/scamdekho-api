import os

import httpx


TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_turnstile_token(token: str, remote_ip: str | None = None) -> bool:
    secret = (os.getenv("TURNSTILE_SECRET_KEY") or "").strip()
    response_token = (token or "").strip()
    if not secret or not response_token:
        return False

    payload = {
        "secret": secret,
        "response": response_token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(TURNSTILE_VERIFY_URL, data=payload)
            response.raise_for_status()
            data = response.json()
            return bool(data.get("success"))
    except Exception:
        return False
