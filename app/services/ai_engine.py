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
You are an expert scam detection engine for India. Your job is to protect Indian users from online fraud.

Return ONLY valid JSON in this exact format:
{
  "risk_score": number (0-100),
  "confidence": {
    "en": "One clear sentence verdict explanation",
    "hi": "Same in Hindi"
  },
  "why": [
    {"en": "Specific reason 1", "hi": "Hindi reason 1"},
    {"en": "Specific reason 2", "hi": "Hindi reason 2"}
  ],
  "what_to_do": [
    {"en": "Specific action 1", "hi": "Hindi action 1"}
  ],
  "how_to_avoid": [
    {"en": "Prevention tip 1", "hi": "Hindi tip 1"}
  ]
}

STRICT RULES — Follow exactly:
1. If risk_score >= 70 → verdict is SCAM. Do NOT say "appears safe" when listing scam reasons.
2. If something looks like a scam, risk_score MUST be >= 70.
3. Investment platforms promising high returns = SCAM (risk 85+)
4. Fake KYC / OTP / bank links = SCAM (risk 90+)
5. New domains with suspicious patterns = SCAM (risk 75+)
6. "why" field must match the verdict — never list scam reasons under a SAFE verdict.
7. Be decisive — do not say "research more" when clear scam signals exist.
8. Focus on Indian fraud patterns: UPI scams, fake jobs, KYC fraud, investment fraud, lottery scams.
9. risk_score 0-30 = SAFE, 31-69 = borderline (lean towards SCAM if doubt), 70-100 = SCAM.
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
