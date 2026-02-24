import os
import json
import base64
from dotenv import load_dotenv
from openai import OpenAI

# Load ENV
load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ===============================
# SYSTEM PROMPT (BILINGUAL + RISK)
# ===============================
SYSTEM_PROMPT = """
You are a high-security scam detection engine for India.

Return ONLY JSON:

{
  "risk_score": number (0-100),
  "confidence": {
    "en": "...",
    "hi": "..."
  },
  "why": [
    {"en": "...", "hi": "..."}
  ],
  "what_to_do": [
    {"en": "...", "hi": "..."}
  ],
  "how_to_avoid": [
    {"en": "...", "hi": "..."}
  ]
}

Rules:
- Informal language does NOT mean scam.
- Indian businesses often use WhatsApp.
- Focus on financial fraud, OTP, KYC, phishing, impersonation.
- Only mark high risk when real scam indicators exist.
"""


# ===============================
# TEXT AI ANALYSIS
# ===============================
def call_ai_analysis(content: str, language="auto", content_type="text"):

    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": content}
            ],
            response_format={"type": "json_object"},
              max_tokens=450
        )

        data = json.loads(response.choices[0].message.content)

        return {
            "risk_score": int(data.get("risk_score", 50)),
            "confidence": data.get("confidence", {}),
            "why": data.get("why", []),
            "what_to_do": data.get("what_to_do", []),
            "how_to_avoid": data.get("how_to_avoid", [])
        }

    except Exception as e:
        print("AI TEXT ERROR:", e)

        return {
            "risk_score": 50,
            "confidence": {
                "en": "Analysis fallback",
                "hi": "विश्लेषण उपलब्ध नहीं"
            },
            "why": [],
            "what_to_do": [],
            "how_to_avoid": []
        }


# ===============================
# IMAGE VISION AI ANALYSIS
# ===============================
def call_ai_vision_analysis(image_bytes):

    try:
        image_b64 = base64.b64encode(image_bytes).decode()

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze this image for scam risk"},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{image_b64}"
                            }
                        }
                    ]
                }
            ],
            response_format={"type": "json_object"},
              max_tokens=450
        )

        data = json.loads(response.choices[0].message.content)

        return {
            "risk_score": int(data.get("risk_score", 50)),
            "confidence": data.get("confidence", {}),
            "why": data.get("why", []),
            "what_to_do": data.get("what_to_do", []),
            "how_to_avoid": data.get("how_to_avoid", [])
        }

    except Exception as e:
        print("VISION AI ERROR:", e)
        return None
