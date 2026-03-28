import os
import json
import base64
import io
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ===============================
# SYSTEM PROMPT — OFFER LETTER
# ===============================
OFFER_LETTER_SYSTEM_PROMPT = """
You are an expert fake document detection engine specializing in Indian job offer letters.

Your job is to analyze the text extracted from an offer letter (PDF or DOC) and determine if it is GENUINE or FAKE/SCAM.

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

FAKE OFFER LETTER SIGNALS — Mark SCAM (risk 70+) if you see:
1. Asks candidate to pay any fee — registration, security deposit, training, uniform, kit fee
2. Salary too high to be real for the role mentioned (e.g. fresher offered ₹5L/month)
3. Company name is misspelled or slightly altered version of a real company (e.g. "Infosys Ltd." vs "Infosys Pvt Ltd India")
4. No proper company address or fake/vague address
5. Unprofessional language, grammar mistakes, inconsistent formatting
6. Email domain is generic (gmail.com, yahoo.com, outlook.com) instead of official company domain
7. No employee ID, reference number, or HR contact name
8. Asks for Aadhaar, PAN, bank details upfront before joining
9. Joining date is unrealistically urgent (e.g. "join within 24 hours")
10. No mention of designation, CTC breakup, or department
11. Offer from a company you never applied to
12. Promises of government job without proper exam/selection process

GENUINE OFFER LETTER SIGNALS — Mark SAFE (risk 0-30) if:
1. Official company domain email (e.g. hr@tcs.com, careers@infosys.com)
2. Proper CTC breakup with components (basic, HRA, PF etc.)
3. Clear designation, department, reporting manager mentioned
4. Realistic salary for the role
5. Proper company letterhead details with CIN/registration number
6. No payment demand of any kind
7. Standard joining formalities (document verification, background check)

RULES:
- DEFAULT IS SAFE — Only mark SCAM if you see CLEAR fraud signals
- risk_score: 0-30 = SAFE (Genuine), 31-69 = SUSPICIOUS, 70-100 = SCAM (Fake)
- "why" must match verdict — never list scam reasons under a SAFE verdict
- When in doubt → give SAFE
"""


# ===============================
# EXTRACT TEXT FROM PDF
# ===============================
def extract_text_from_pdf(file_bytes: bytes) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text.strip()
    except Exception as e:
        print("PDF EXTRACT ERROR:", e)
        return ""


# ===============================
# EXTRACT TEXT FROM DOC/DOCX
# ===============================
def extract_text_from_doc(file_bytes: bytes) -> str:
    try:
        import docx
        doc = docx.Document(io.BytesIO(file_bytes))
        text = "\n".join([para.text for para in doc.paragraphs])
        return text.strip()
    except Exception as e:
        print("DOC EXTRACT ERROR:", e)
        return ""


# ===============================
# AI ANALYSIS — OFFER LETTER
# ===============================
def analyze_offer_letter_ai(extracted_text: str) -> dict:
    try:
        prompt = f"""Analyze this offer letter text and determine if it is GENUINE or FAKE/SCAM.

OFFER LETTER CONTENT:
{extracted_text[:4000]}

Be thorough. Check for all fraud signals mentioned in your instructions."""

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": OFFER_LETTER_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
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
        print("OFFER LETTER AI ERROR:", e)
        return {
            "risk_score": 50,
            "confidence": {
                "en": "Analysis could not be completed. Please try again.",
                "hi": "विश्लेषण पूरा नहीं हो सका। कृपया पुनः प्रयास करें।"
            },
            "why": [],
            "what_to_do": [],
            "how_to_avoid": []
        }
def analyze_offer_letter_pdf_vision(file_bytes: bytes) -> dict:
    try:
        import fitz
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        all_results = []
        for page_num, page in enumerate(doc):
            if page_num >= 3:
                break
            pix = page.get_pixmap(dpi=150)
            img_bytes = pix.tobytes("png")
            img_b64 = base64.b64encode(img_bytes).decode()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": OFFER_LETTER_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Analyze page {page_num+1} of this offer letter. Is it GENUINE or FAKE/SCAM?"},
                            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img_b64}"}}
                        ]
                    }
                ],
                response_format={"type": "json_object"},
            )
            data = json.loads(response.choices[0].message.content)
            all_results.append(data)
        if not all_results:
            return {"risk_score": 50, "confidence": {"en": "Could not analyze", "hi": "विश्लेषण विफल"}, "why": [], "what_to_do": [], "how_to_avoid": []}
        best = max(all_results, key=lambda x: x.get("risk_score", 0))
        return {
            "risk_score": int(best.get("risk_score", 50)),
            "confidence": best.get("confidence", {}),
            "why": best.get("why", []),
            "what_to_do": best.get("what_to_do", []),
            "how_to_avoid": best.get("how_to_avoid", [])
        }
    except Exception as e:
        print("PDF VISION ERROR:", e)
        return {"risk_score": 50, "confidence": {"en": "Analysis failed", "hi": "विश्लेषण विफल"}, "why": [], "what_to_do": [], "how_to_avoid": []}
