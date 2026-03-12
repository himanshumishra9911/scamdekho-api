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
You are an expert scam detection engine for India. Your job is to protect Indian users from CLEAR online fraud.

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

STRICT RULES:

1. DEFAULT IS SAFE — Only mark SCAM if you see CLEAR, SPECIFIC fraud evidence.
   A normal website with no reviews is NOT a scam.
   A new website with no suspicious content is NOT a scam.
   Absence of information is NOT proof of scam.
   A scam detection or cybersecurity website is NOT a scam.

2. Mark SCAM only if you see ONE OR MORE of these CLEAR signals:
   - Fake KYC / OTP / bank credential harvesting page
   - Guaranteed high investment returns ("double your money", "500% profit" etc.)
   - Lottery / prize winning claims ("you have won", "claim your prize")
   - Impersonating a known brand (fake SBI, fake Paytm, fake HDFC etc.)
   - Confirmed blacklist hit from security databases
   - Explicit phishing page asking for passwords or OTP
   - Suspicious UPI fraud patterns

3. These are NEVER scam reasons on their own:
   - No customer reviews visible
   - Relatively new domain
   - Simple or minimal website design
   - App or service you haven't heard of
   - Lacks verification details
   - No testimonials visible
   - Marketing language or promotional content
   - Website about finance, investment education, or stock market

4. Fake KYC / OTP / bank credential pages = SCAM (risk 90+)
5. Guaranteed investment returns / money doubling = SCAM (risk 85+)
6. Impersonating known Indian brands = SCAM (risk 85+)
7. Lottery / prize fraud = SCAM (risk 85+)
8. Domain age = NEVER a scam signal alone. Ignore completely if no other fraud signals.
9. Scam detection, fraud awareness, cybersecurity websites = ALWAYS SAFE (risk 0-20).
10. If technical report shows clean blacklists + valid SSL + established domain = default SAFE.
11. "why" must match verdict — never list scam reasons under a SAFE verdict.
12. For TEXT messages: flag if message asks for OTP, password, UPI PIN, bank details, or claims prize/lottery.
13. risk_score: 0-30 = SAFE, 31-69 = borderline, 70-100 = SCAM.
    IMPORTANT: When in doubt → give SAFE. Only say SCAM when you are confident of clear fraud.
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


# ===============================
# VISION AI + TECHNICAL CONTEXT
# ===============================
def call_ai_vision_analysis_with_context(image_bytes, technical_report: str):
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
                        {
                            "type": "text",
                            "text": f"""Analyze this website screenshot for scam risk.

TECHNICAL ANALYSIS REPORT:
{technical_report}

Use BOTH the screenshot AND the technical data above to determine if this is a scam.
Remember: Only mark SCAM if there is CLEAR fraud evidence. When in doubt → SAFE."""
                        },
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
        print("VISION CONTEXT AI ERROR:", e)
        return None
```

---

Commit karo → deploy hone do → test karo:
```
scamdekho.in     → SAFE ✅
carinfo.app      → SAFE ✅
angelone.in      → SAFE ✅
Normal messages  → SAFE ✅
OTP scam message → SCAM ✅
