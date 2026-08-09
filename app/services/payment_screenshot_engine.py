# -*- coding: utf-8 -*-
"""Evidence-based payment screenshot authenticity analysis.

The model observes the screenshot; deterministic code owns the public verdict.
This separation prevents missing fields, an unfamiliar app, or suspicious payment
content from being treated as proof that the pixels were manipulated.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from statistics import mean
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field

from app.services.payment_local_forensics import (
    LocalForensicsResult,
    _explicit_overlay_term,
    analyze_local_forensics,
)

try:
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover - dependency is present in production
    pass

load_dotenv()
logger = logging.getLogger(__name__)

ANALYSIS_VERSION = "payment-vision-v31"
# GPT-5 mini is the highest-quality direct-vision model that still fits the
# product's measured ~$0.0014/check operating envelope.  Confirmed local
# signatures and cache hits continue to bypass the model entirely.
PRIMARY_MODEL = os.getenv("PAYMENT_SCREENSHOT_MODEL", "gpt-5-mini")
REPLICA_MODEL = os.getenv("PAYMENT_SCREENSHOT_REPLICA_MODEL", PRIMARY_MODEL)
CHEAP_REVIEW_MODEL = os.getenv(
    "PAYMENT_SCREENSHOT_CHEAP_REVIEW_MODEL", "gpt-5.4-nano"
)
REVIEW_MODEL = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODEL", "gpt-5.4-nano")
ADJUDICATOR_MODEL = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODEL", "gpt-5.4-nano")
REVIEW_MODE = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODE", "suspicious").strip().lower()
ADJUDICATOR_MODE = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODE", "adaptive").strip().lower()
BASE_REASONING_EFFORT = os.getenv("PAYMENT_SCREENSHOT_REASONING_EFFORT", "none")
PRIMARY_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_PRIMARY_REASONING_EFFORT", BASE_REASONING_EFFORT
)
REPLICA_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_REPLICA_REASONING_EFFORT", "none"
)
CHEAP_REVIEW_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_CHEAP_REVIEW_REASONING_EFFORT", "none"
)
REVIEW_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_REVIEW_REASONING_EFFORT", "none"
)
ADJUDICATOR_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_EFFORT", "none"
)
ADJUDICATOR_REASONING_MODE = os.getenv(
    "PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_MODE", "standard"
).strip().lower()
PRIMARY_IMAGE_DETAIL = os.getenv("PAYMENT_SCREENSHOT_PRIMARY_IMAGE_DETAIL", "low")
REPLICA_IMAGE_DETAIL = os.getenv("PAYMENT_SCREENSHOT_REPLICA_IMAGE_DETAIL", "low")
REVIEW_IMAGE_DETAIL = os.getenv("PAYMENT_SCREENSHOT_REVIEW_IMAGE_DETAIL", "auto")
ADJUDICATOR_IMAGE_DETAIL = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_IMAGE_DETAIL", "auto")
OUTPUT_VERBOSITY = (
    os.getenv("PAYMENT_SCREENSHOT_OUTPUT_VERBOSITY", "low").strip().lower()
)
if OUTPUT_VERBOSITY not in {"low", "medium", "high"}:
    OUTPUT_VERBOSITY = "low"
MODEL_TIMEOUT_SECONDS = float(os.getenv("PAYMENT_SCREENSHOT_MODEL_TIMEOUT", "25"))
MAX_IMAGE_PIXELS = int(os.getenv("PAYMENT_SCREENSHOT_MAX_PIXELS", "40000000"))
MAX_ANALYSIS_VIEWS = max(1, min(3, int(os.getenv("PAYMENT_SCREENSHOT_MAX_VIEWS", "2"))))
PRIMARY_MAX_ANALYSIS_VIEWS = min(
    MAX_ANALYSIS_VIEWS,
    max(1, min(3, int(os.getenv("PAYMENT_SCREENSHOT_PRIMARY_MAX_VIEWS", "1")))),
)
REVIEW_MAX_ANALYSIS_VIEWS = min(
    MAX_ANALYSIS_VIEWS,
    max(1, min(3, int(os.getenv("PAYMENT_SCREENSHOT_REVIEW_MAX_VIEWS", "2")))),
)
ADJUDICATOR_MAX_ANALYSIS_VIEWS = min(
    MAX_ANALYSIS_VIEWS,
    max(1, min(3, int(os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MAX_VIEWS", "2")))),
)
PRIMARY_MAX_OUTPUT_TOKENS = int(os.getenv("PAYMENT_SCREENSHOT_PRIMARY_MAX_OUTPUT_TOKENS", "1100"))
REPLICA_MAX_OUTPUT_TOKENS = int(os.getenv("PAYMENT_SCREENSHOT_REPLICA_MAX_OUTPUT_TOKENS", "800"))
CHEAP_REVIEW_MAX_OUTPUT_TOKENS = int(
    os.getenv("PAYMENT_SCREENSHOT_CHEAP_REVIEW_MAX_OUTPUT_TOKENS", "1100")
)
REVIEW_MAX_OUTPUT_TOKENS = int(os.getenv("PAYMENT_SCREENSHOT_REVIEW_MAX_OUTPUT_TOKENS", "1500"))
ADJUDICATOR_MAX_OUTPUT_TOKENS = int(
    os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MAX_OUTPUT_TOKENS", "1800")
)
BUDGET_TARGET_USD_PER_CHECK = float(
    os.getenv("PAYMENT_SCREENSHOT_BUDGET_TARGET_USD", "0.0014")
)

MODEL_SCORE_WEIGHT = 0.75
FORENSIC_SCORE_WEIGHT = 0.25
SAFE_MAX_SCORE = 34
SCAM_MIN_SCORE = 70

# Standard API prices per one million tokens. These values are used only for
# request telemetry; billing remains authoritative in the OpenAI dashboard.
MODEL_PRICING_USD_PER_MTOK = {
    "gpt-5-nano": {"input": 0.05, "cached_input": 0.005, "output": 0.4},
    "gpt-5-mini": {"input": 0.25, "cached_input": 0.025, "output": 2.0},
    "gpt-5.4-nano": {"input": 0.2, "cached_input": 0.02, "output": 1.25},
    "gpt-5.4-mini": {"input": 0.75, "cached_input": 0.075, "output": 4.5},
    "gpt-5.6-sol": {"input": 5.0, "cached_input": 0.5, "output": 30.0},
    "gpt-5.6-terra": {"input": 2.5, "cached_input": 0.25, "output": 15.0},
    "gpt-5.6-luna": {"input": 1.0, "cached_input": 0.1, "output": 6.0},
}


class ExtractedFields(BaseModel):
    amount: str | None
    transaction_id: str | None
    upi_id: str | None
    recipient_name: str | None
    sender_name: str | None
    bank_name: str | None
    timestamp: str | None
    status_text: str | None
    transaction_label: str | None = None


class VisualEvidence(BaseModel):
    category: Literal[
        "overlay",
        "typography",
        "alignment",
        "branding",
        "pixel_artifact",
        "replica_app",
        "transaction_data",
        "other",
    ]
    strength: Literal["weak", "moderate", "strong"]
    description: str
    location: str | None
    observed_text: str | None


class PaymentObservation(BaseModel):
    app_name: str
    app_key: str
    app_confidence: int = Field(ge=0, le=100)
    screenshot_kind: Literal[
        "payment_success",
        "payment_pending",
        "payment_failed",
        "payment_request",
        "receipt_or_history",
        "other",
        "unreadable",
    ]
    readability: Literal["clear", "partial", "unreadable"]
    payment_state: Literal["success", "pending", "failed", "request", "unknown"]
    fields: ExtractedFields
    tampering_evidence: list[VisualEvidence]
    impossible_inconsistencies: list[str]
    benign_limitations: list[str]
    content_risk_signals: list[str]
    authenticity_assessment: Literal[
        "no_evidence_of_manipulation", "uncertain", "clear_manipulation"
    ]
    fake_probability: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    reasons: list[str]


class ReplicaTriage(BaseModel):
    """Compact second opinion optimized for fake/clone payment-app screens."""

    app_name: str
    app_key: str
    app_confidence: int = Field(ge=0, le=100)
    headline_text: str | None
    transaction_label: str | None
    transaction_id: str | None
    amount: str | None
    upi_id: str | None
    recipient_name: str | None
    sender_name: str | None
    bank_name: str | None
    timestamp: str | None
    readability: Literal["clear", "partial", "unreadable"]
    wording_errors: list[str]
    app_identity_conflicts: list[str]
    transaction_format_anomalies: list[str]
    component_style_conflicts: list[str]
    benign_explanations: list[str]
    assessment: Literal["likely_genuine", "uncertain", "likely_replica"]
    replica_probability: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    reasons: list[str]


@dataclass
class ModelPassResult:
    observation: PaymentObservation
    model: str
    view_count: int
    role: str = ""
    input_tokens: int = 0
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float | None = None
    latency_ms: int = 0
    raw_model_score: int | None = None


SYSTEM_PROMPT = """You assess whether an Indian payment screenshot was fabricated or edited. This includes a coherent screen rendered by a fake or clone payment app, not only a pasted value in a real-app screenshot.

The task is screenshot authenticity, not confirmation that money reached an account. A visually genuine screenshot can still show a failed, pending, requested, reversed, old, or fraudulent transaction. Record those facts separately.

Use only visible evidence. Payment app layouts change by app version, OS, language, theme, device size, account type, merchant flow, and A/B test. Unknown or regional apps are normal. Never invent an official layout from memory.

These are NOT tampering evidence by themselves: crop; compression; blur; missing status bar; missing UPI ID, bank, sender, reference number, date, or time; a non-12-digit or alphanumeric reference; old or future date; dark mode; unusual font caused by OS accessibility; cross-app UPI handles or branding; merchant handles; suspicious words in a name or UPI ID; or a simple/clean design.

Treat normal presentation variants as benign unless there is independent, localized evidence of editing. Examples include masked identifiers, decorative receipts, minimal share receipts, large black or white viewer margins, OS/share-sheet chrome, ads, cashback or rewards panels, and receipts embedded inside another app or image viewer. A full transaction page and a shared receipt for the same payment can look substantially different. The status-bar time may reflect when the receipt was viewed rather than when the payment happened.

An in-app advertisement or promotion below/around a receipt is normal product UI, not proof that the screenshot was composited. Likewise, a status-bar time equal to the visible payment time is internally consistent, not an anomaly. Never place either observation in tampering_evidence unless a separate localized pixel artifact is visible.

An explicit visible label such as FAKE, fake payment, screenshot generator, prank,
demo, or test payment is not a benign wrapper. It directly establishes that the
presented image is not an unmodified, genuine payment proof. A watermark or
graphic that materially covers the payment receipt is also manipulation of the
presented screenshot even if the receipt underneath resembles a real app.

A large third-party warning annotation such as "scam", "fraud", "savdhan", or
"beware" overlapping receipt controls establishes that the presented screenshot
was annotated/edited and must not be called visually genuine. Report it as
uncertain manipulation unless separate visible evidence proves the underlying
transaction UI itself was fabricated. Do not convert a warning caption alone
into a claim that the underlying bank transaction was fake.

Strong evidence must be specific and visible, such as a localized paste boundary, inconsistent anti-aliasing around an edited value, an impossible internal contradiction visible in two fields, or a clearly composited logo/status element. Name its location. If a benign explanation is plausible, use weak/moderate evidence or no evidence.

A fake-app screen may be internally clean and have no paste boundary. Consider replica_app evidence only when at least two independent, visible inconsistencies occur inside the payment UI, for example a stable grammatical error in a system heading plus mixed branding/component styles, or mutually incompatible app identity elements. A single typo, unfamiliar layout, missing transaction details, absent reference number, or the recipient saying money was not received is not enough. Use moderate replica_app evidence and uncertain when the combination is concerning but not decisive; use strong only when the visible combination has no plausible app-version, theme, language, accessibility, crop, compression, or OCR explanation.

Do not overcorrect this rule by ignoring transaction identifiers. Identifier length or format alone is benign, but when the app identity is highly confident, a provider-label/identifier mismatch can be one replica signal if a separate wording, branding, component, or bank-identity inconsistency is also visible. Judge the combination, not a remembered template.

When a payment receipt is forwarded inside WhatsApp, SMS, a gallery, or another viewer, treat the surrounding wrapper as context rather than part of the payment app. Inspect the embedded receipt separately and do not mistake wrapper fonts, status bars, or compression for receipt tampering.

Populate every schema field. Put possible scam context in content_risk_signals, never in tampering_evidence unless it also supports visible screenshot fabrication or editing."""


ANALYST_PROMPT = """Inspect the whole screenshot carefully.

1. Identify the paying app only when supported by visible UI branding; otherwise use Unknown. Never infer the paying app from a recipient UPI handle or bank name.
2. Transcribe the success heading, transaction-ID label/value, and other visible fields exactly; do not silently correct spelling.
3. Separate payment state from screenshot authenticity.
4. Look for localized editing artifacts, impossible internal contradictions, and combinations of replica-app signals. A clean fake-app render may have no paste boundary.
5. List benign limitations so they are not reused as fraud evidence.
6. Estimate fake_probability for screenshot fabrication/editing only.

Use clear_manipulation only when at least one strong, specific item exists in tampering_evidence or an impossible contradiction is directly visible."""


REPLICA_TRIAGE_PROMPT = """Judge the authenticity of this submitted payment screenshot directly from its pixels. Classify it as likely_genuine, uncertain, or likely_replica. This is screenshot authenticity, not proof that bank settlement occurred.

Identify the paying app only from visible UI branding. Transcribe the heading, transaction label/ID, amount, UPI ID, names, bank, and time exactly; use null when unreadable. Never infer the app from a UPI-handle domain or bank.

Look for independent visible signals across: (1) system wording, (2) app/provider identity, (3) transaction-label/ID coherence, and (4) component, icon, bank, or pixel style. Fake-app screens can be pixel-clean. A single typo, unfamiliar layout, crop, compression, missing field, short/alphanumeric ID, cross-app handle, ad, reward panel, theme, language, OS, or app-version difference is not manipulation. Use likely_replica only for clear editing or at least two mutually supporting signal families with no plausible benign explanation.

A third-party fake/generator label establishes a fabricated presented image. A scam/fraud/savdhan/beware caption overlapping receipt controls establishes an annotated image: use uncertain unless separate evidence proves the underlying UI was fabricated.

Set replica_probability continuously: 0-34 likely_genuine, 35-69 uncertain, 70-100 likely_replica. Do not default to round template values such as 25/50/75/99; vary it with evidence quantity, independence, visibility, and strength. An overlapping warning annotation is normally 45-69.

Keep every evidence/limitation/reason list to at most two short items and each item under 16 words. Populate every schema field."""


REPLICA_REVIEW_PROMPT = """Inspect the screenshot independently as a fake/clone payment-app specialist.

Look for combinations of internally inconsistent app identity, system wording, component families, icon geometry, spacing, duplicated/overlapping/ghosted elements (including the status bar), and transaction fields. Transcribe the success heading exactly and never derive the paying-app identity from a UPI handle. Then try to falsify every suspected signal using app-version, OS, language, theme, merchant-flow, accessibility, crop, and compression explanations. A single typo, missing field, unfamiliar layout, or non-receipt claim is not enough. Inspect an embedded receipt separately from any chat, gallery, or SMS wrapper.

Treat a confidently branded screen with three or more independent, visible conflicts across system wording, provider-specific labels/identifier coherence, banking-name semantics, and component/bank identity as strong clone-app evidence when those conflicts cannot be explained by a merchant flow or app variation. This is a combination rule, not a fixed-template rule; each item alone remains benign.

Return no_evidence_of_manipulation when there is no specific visible evidence. Return uncertain for a concerning but non-decisive combination. Return clear_manipulation only for strong, specific visible evidence."""


ADJUDICATOR_PROMPT = """Perform a forensic adjudication of this payment screenshot.

First search for evidence that a fake could have introduced. Then actively try to explain each anomaly through compression, crop, app/OS version, theme, language, accessibility, merchant flow, or unreadable text. Candidate signals from cheaper reviewers may be supplied; treat them only as hypotheses and verify each directly against visible pixels. Do not assume a popular app's remembered layout is current. Prefer uncertain over clear_manipulation when evidence cannot be localized. Populate every schema field."""


VERDICT_LABELS = {
    "SAFE": {
        "en": "No clear visual evidence of screenshot manipulation was found.",
        "hi": "Screenshot में बदलाव या छेड़छाड़ का कोई स्पष्ट visual evidence नहीं मिला।",
    },
    "SUSPICIOUS": {
        "en": "Inconclusive - verify the payment in your own account.",
        "hi": "नतीजा स्पष्ट नहीं है — payment को अपने account में verify करें।",
    },
    "SCAM": {
        "en": "High risk - clear signs of screenshot manipulation were found.",
        "hi": "High risk — screenshot में छेड़छाड़ के स्पष्ट संकेत मिले हैं।",
    },
}

WHAT_TO_DO = {
    "SAFE": [
        {
            "en": "Verify the credit in your own bank or UPI app before releasing goods.",
            "hi": "Goods देने से पहले अपने bank या UPI app में credit verify करें।",
        },
        {
            "en": "A visually genuine screenshot is not proof that the payment settled.",
            "hi": "Visually genuine screenshot भी payment settle होने का proof नहीं है।",
        },
    ],
    "SUSPICIOUS": [
        {
            "en": "Do not accept this screenshot as payment proof; check your own account.",
            "hi": "इसे payment proof न मानें; अपना account check करें।",
        },
        {
            "en": "Ask the sender to show the transaction live in their UPI app.",
            "hi": "Sender से अपने UPI app में live transaction दिखाने को कहें।",
        },
        {
            "en": "Do not release goods or services until the credit is visible to you.",
            "hi": "Credit दिखने तक goods या services न दें।",
        },
    ],
    "SCAM": [
        {
            "en": "Do not accept this screenshot as payment proof.",
            "hi": "इस screenshot को payment proof न मानें।",
        },
        {
            "en": "Check your own account and preserve the chat and screenshot as evidence.",
            "hi": "अपना account check करें और chat व screenshot को evidence के रूप में रखें।",
        },
        {
            "en": "If money or goods were lost, report at cybercrime.gov.in or call 1930.",
            "hi": "नुकसान हुआ हो तो cybercrime.gov.in पर report करें या 1930 call करें।",
        },
    ],
}

HOW_TO_AVOID = [
    {
        "en": "Always confirm incoming credit in your own UPI app, bank app, or statement.",
        "hi": "Incoming credit हमेशा अपने UPI app, bank app या statement में confirm करें।",
    },
    {
        "en": "Match the amount, payer, time, and reference with your own transaction history.",
        "hi": "Amount, payer, time और reference को अपनी transaction history से match करें।",
    },
    {
        "en": "Never release goods or services based only on a screenshot.",
        "hi": "सिर्फ screenshot देखकर goods या services कभी न दें।",
    },
]


def get_client() -> OpenAI:
    return OpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        timeout=MODEL_TIMEOUT_SECONDS,
        max_retries=0,
    )


def _prepare_image(image_bytes: bytes) -> tuple[bytes, str, tuple[int, int]]:
    """Validate pixels and convert HEIC/HEIF to a model-supported JPEG."""
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError("Could not decode this image. Upload a clear PNG, JPEG, WebP or HEIC file.") from exc

    width, height = image.size
    if width < 200 or height < 200:
        raise ValueError("Image dimensions are too small. Upload the full payment screen.")
    if width * height > MAX_IMAGE_PIXELS:
        raise ValueError("Image resolution is too large. Upload an image under 40 megapixels.")

    image_format = (image.format or "").upper()
    media_types = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
    if image_format in media_types:
        return image_bytes, media_types[image_format], (width, height)

    if image_format in {"HEIC", "HEIF", "AVIF"}:
        converted = ImageOps.exif_transpose(image).convert("RGB")
        output = io.BytesIO()
        converted.save(output, format="JPEG", quality=95, optimize=True)
        return output.getvalue(), "image/jpeg", (width, height)

    raise ValueError("Unsupported decoded image format. Upload PNG, JPEG, WebP or HEIC.")


def _image_data_url(image_bytes: bytes, media_type: str) -> str:
    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


AnalysisView = tuple[str, bytes, str]


def _encode_png(image: Image.Image) -> bytes:
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _make_analysis_views(
    image_bytes: bytes,
    media_type: str,
    max_views: int | None = None,
) -> list[AnalysisView]:
    """Keep the full image and add overlapping native-resolution crops for tiny text."""
    view_limit = MAX_ANALYSIS_VIEWS if max_views is None else max(1, min(3, max_views))
    views: list[AnalysisView] = [("Full screenshot", image_bytes, media_type)]
    if view_limit == 1:
        return views

    with Image.open(io.BytesIO(image_bytes)) as image:
        image.load()
        width, height = image.size
        if height >= width * 1.45:
            crop_height = round(height * 0.62)
            crops = [
                ("Upper payment area", image.crop((0, 0, width, crop_height))),
                ("Lower details area", image.crop((0, height - crop_height, width, height))),
            ]
        elif width >= height * 1.45:
            crop_width = round(width * 0.62)
            crops = [
                ("Left payment area", image.crop((0, 0, crop_width, height))),
                ("Right payment area", image.crop((width - crop_width, 0, width, height))),
            ]
        else:
            return views

        for label, crop in crops[: view_limit - 1]:
            views.append((label, _encode_png(crop), "image/png"))
    return views


def _usage_value(container: object, name: str) -> int:
    if container is None:
        return 0
    if isinstance(container, dict):
        value = container.get(name, 0)
    else:
        value = getattr(container, name, 0)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _model_pricing(model: str) -> dict[str, float] | None:
    for model_prefix, prices in MODEL_PRICING_USD_PER_MTOK.items():
        if model == model_prefix or model.startswith(f"{model_prefix}-"):
            return prices
    return None


def _estimate_cost_usd(
    model: str,
    input_tokens: int,
    cached_input_tokens: int,
    cache_write_tokens: int,
    output_tokens: int,
) -> float | None:
    prices = _model_pricing(model)
    if prices is None:
        return None

    cached = min(input_tokens, cached_input_tokens)
    uncached = max(0, input_tokens - cached)
    # Cache-write tokens are already input tokens; add only the 25% write premium.
    cost = (
        uncached * prices["input"]
        + cached * prices["cached_input"]
        + cache_write_tokens * prices["input"] * 0.25
        + output_tokens * prices["output"]
    ) / 1_000_000
    return round(cost, 6)


def _model_pass_result(
    response: object,
    observation: PaymentObservation,
    model: str,
    view_count: int,
    latency_ms: int = 0,
    raw_model_score: int | None = None,
) -> ModelPassResult:
    usage = getattr(response, "usage", None)
    input_details = (
        usage.get("input_tokens_details")
        if isinstance(usage, dict)
        else getattr(usage, "input_tokens_details", None)
    )
    output_details = (
        usage.get("output_tokens_details")
        if isinstance(usage, dict)
        else getattr(usage, "output_tokens_details", None)
    )
    input_tokens = _usage_value(usage, "input_tokens")
    cached_input_tokens = _usage_value(input_details, "cached_tokens")
    cache_write_tokens = _usage_value(input_details, "cache_write_tokens")
    output_tokens = _usage_value(usage, "output_tokens")
    reasoning_tokens = _usage_value(output_details, "reasoning_tokens")
    total_tokens = _usage_value(usage, "total_tokens") or input_tokens + output_tokens
    return ModelPassResult(
        observation=observation,
        model=model,
        view_count=view_count,
        input_tokens=input_tokens,
        cached_input_tokens=cached_input_tokens,
        cache_write_tokens=cache_write_tokens,
        output_tokens=output_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=_estimate_cost_usd(
            model,
            input_tokens,
            cached_input_tokens,
            cache_write_tokens,
            output_tokens,
        ),
        latency_ms=latency_ms,
        raw_model_score=(
            raw_model_score
            if raw_model_score is not None
            else observation.fake_probability
        ),
    )


def _normalize_image_detail(value: str, fallback: str) -> str:
    clean = str(value or "").strip().lower()
    return clean if clean in {"low", "auto", "high", "original"} else fallback


def _request_policy(prompt: str) -> tuple[str, int]:
    if prompt == ANALYST_PROMPT:
        return _normalize_image_detail(PRIMARY_IMAGE_DETAIL, "low"), PRIMARY_MAX_OUTPUT_TOKENS
    if prompt == REPLICA_REVIEW_PROMPT:
        return _normalize_image_detail(REVIEW_IMAGE_DETAIL, "auto"), REVIEW_MAX_OUTPUT_TOKENS
    return (
        _normalize_image_detail(ADJUDICATOR_IMAGE_DETAIL, "auto"),
        ADJUDICATOR_MAX_OUTPUT_TOKENS,
    )


def _reasoning_config(
    model: str,
    reasoning_effort: str,
    reasoning_mode: str,
) -> dict[str, str] | None:
    # GPT-5 Nano supports image input and structured output but not reasoning
    # tokens. Sending a reasoning block makes the fast passes fail before
    # inference, so omit it entirely for that model.
    normalized_model = model.strip().lower()
    if normalized_model == "gpt-5-nano" or not reasoning_effort:
        return None
    if normalized_model.startswith("gpt-5-mini") and reasoning_effort == "none":
        reasoning_effort = "minimal"
    reasoning = {"effort": reasoning_effort}
    if reasoning_mode == "pro" and normalized_model.startswith("gpt-5.6"):
        reasoning["mode"] = "pro"
    return reasoning


def _run_typed_model(
    image_views: list[AnalysisView],
    prompt: str,
    model: str,
    reasoning_effort: str,
    reasoning_mode: str,
    text_format: type[BaseModel],
    image_detail: str,
    max_output_tokens: int,
) -> tuple[object, BaseModel, int]:
    content: list[dict] = [{"type": "input_text", "text": prompt}]
    for label, view_bytes, view_media_type in image_views:
        content.extend(
            [
                {"type": "input_text", "text": label},
                {
                    "type": "input_image",
                    "image_url": _image_data_url(view_bytes, view_media_type),
                    "detail": image_detail,
                },
            ]
        )

    request_kwargs: dict = {
        "model": model,
        "instructions": SYSTEM_PROMPT,
        "input": [
            {
                "role": "user",
                "content": content,
            }
        ],
        "text_format": text_format,
        "max_output_tokens": max_output_tokens,
        "text": {"verbosity": OUTPUT_VERBOSITY},
        "prompt_cache_key": (
            f"{ANALYSIS_VERSION}:{model}:"
            f"{hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:12]}"
        ),
        "store": False,
    }
    reasoning = _reasoning_config(model, reasoning_effort, reasoning_mode)
    if reasoning is not None:
        request_kwargs["reasoning"] = reasoning

    started_at = time.perf_counter()
    response = get_client().responses.parse(**request_kwargs)
    latency_ms = round((time.perf_counter() - started_at) * 1000)
    if response.output_parsed is None:
        raise ValueError("The vision model did not return a usable forensic report.")
    return response, response.output_parsed, latency_ms


def _run_model(
    image_views: list[AnalysisView],
    prompt: str,
    model: str,
    reasoning_effort: str,
    reasoning_mode: str = "standard",
) -> ModelPassResult:
    image_detail, max_output_tokens = _request_policy(prompt)
    response, observation, latency_ms = _run_typed_model(
        image_views,
        prompt,
        model,
        reasoning_effort,
        reasoning_mode,
        PaymentObservation,
        image_detail,
        max_output_tokens,
    )
    return _model_pass_result(
        response,
        observation,
        model,
        len(image_views),
        latency_ms,
    )


def _is_negated_evidence_claim(claim: str) -> bool:
    """Do not turn a model's explicit absence statement into evidence."""
    normalized = " ".join(claim.casefold().split())
    return any(
        marker in normalized
        for marker in (
            "no clear ",
            "no obvious ",
            "no visible ",
            "no specific ",
            "no evidence",
            "no sign of",
            "no signs of",
            "none detected",
            "not detected",
            "not visible",
            "without any ",
            "does not show",
            "cannot identify",
        )
    )


def _is_benign_replica_claim(group_name: str, claim: str) -> bool:
    """Reject common model claims that the prompt explicitly defines as benign."""
    normalized = " ".join(claim.casefold().split())
    if _is_negated_evidence_claim(claim):
        return True
    soft_wording_markers = (
        "capitalization",
        "pluralization",
        "casing",
        "spacing",
        "rather than a standard",
        "non-screenshot-heading phrasing",
        "thanksapp",
        "airtel thanks app",
        "footer brand",
        "no obvious spelling",
        "masked",
        "partial",
        "receipt-style",
        "generic heading",
        "powered by",
    )
    interoperability_markers = (
        "recipient line",
        "recipient row",
        "sent to",
        "paid to",
        "received from",
        "upi handle",
        "handle domain",
        "bank/provider",
        "bank identity",
        "bank of",
        "banking name",
        "payments bank",
        "powered by",
        "partner branding",
        "separate partner",
        "provider branding",
        "provider logo",
        "text branding",
        "monogram",
        "footer",
    )
    presentation_markers = (
        "share receipt",
        "receipt composition",
        "receipt-style",
        "not shown",
        "missing",
        "only implied",
        "masked",
        "truncation",
        "avatar",
        "generic",
        "future date",
        "timestamp",
    )
    if group_name == "wording" and any(
        heading in normalized
        for heading in _SUSPICIOUS_SUCCESS_HEADINGS
    ):
        return False
    if group_name == "wording":
        return any(marker in normalized for marker in soft_wording_markers)
    if group_name in {"app identity", "component style"}:
        return any(
            marker in normalized
            for marker in interoperability_markers + presentation_markers
        )
    return False


def _is_objective_wording_claim(claim: str) -> bool:
    normalized = claim.casefold()
    return any(
        marker in normalized
        for marker in (
            "misspell",
            "spelling error",
            "grammatical error",
            "extra letter",
            "wrong spelling",
        )
    )


def _is_objective_visual_claim(claim: str) -> bool:
    normalized = claim.casefold()
    return any(
        marker in normalized
        for marker in (
            "paste boundary",
            "hard edge",
            "hard rectangular edge",
            "pixel artifact",
            "pixelated",
            "anti-alias",
            "halo around",
            "different resolution",
            "composite boundary",
            "duplicat",
            "overlap",
            "ghost",
            "double-render",
            "merged glyph",
            "smear",
        )
    )


def _replica_triage_to_observation(triage: ReplicaTriage) -> PaymentObservation:
    raw_signal_groups = [
        ("wording", triage.wording_errors, "weak"),
        ("app identity", triage.app_identity_conflicts, "weak"),
        ("transaction format", triage.transaction_format_anomalies, "weak"),
        ("component style", triage.component_style_conflicts, "weak"),
    ]
    filtered_claims: list[str] = []
    signal_groups: list[tuple[str, list[str], str]] = []
    for group_name, items, strength in raw_signal_groups:
        accepted: list[str] = []
        for item in items:
            if _is_benign_replica_claim(group_name, item):
                filtered_claims.append(item)
            else:
                accepted.append(item)
        if group_name == "wording":
            objective = [item for item in accepted if _is_objective_wording_claim(item)]
            semantic = [item for item in accepted if item not in objective]
            signal_groups.append(("wording", objective, "moderate"))
            signal_groups.append(("wording variant", semantic, "weak"))
        elif group_name == "component style":
            objective = [item for item in accepted if _is_objective_visual_claim(item)]
            semantic = [item for item in accepted if item not in objective]
            signal_groups.append(("visual component", objective, "moderate"))
            signal_groups.append(("component style", semantic, "weak"))
        else:
            signal_groups.append((group_name, accepted, strength))

    independent_groups = sum(bool(items) for _, items, _ in signal_groups)
    material_groups = sum(
        bool(items) for _, items, strength in signal_groups if strength != "weak"
    )
    model_confirmed_replica = (
        triage.assessment == "likely_replica"
        and triage.replica_probability >= 80
        and independent_groups >= 3
        and material_groups >= 2
    )
    high_confidence_multisignal_replica = (
        triage.assessment == "uncertain"
        and triage.app_confidence >= 75
        and triage.replica_probability >= 70
        and independent_groups >= 3
        and material_groups >= 2
    )
    confirmed_replica = model_confirmed_replica or high_confidence_multisignal_replica
    evidence: list[VisualEvidence] = []
    promoted_strong = False
    for group_name, items, default_strength in signal_groups:
        for item in items[:3]:
            strength = default_strength
            if confirmed_replica and default_strength == "moderate" and not promoted_strong:
                strength = "strong"
                promoted_strong = True
            evidence.append(
                VisualEvidence(
                    category="replica_app",
                    strength=strength,
                    description=f"{group_name.title()} inconsistency: {item}",
                    location="payment interface",
                    observed_text=item,
                )
            )

    has_material_signal = any(
        item.strength in {"moderate", "strong"} for item in evidence
    )
    assessment = (
        "clear_manipulation"
        if confirmed_replica
        else "uncertain"
        if has_material_signal
        else "no_evidence_of_manipulation"
    )
    calibrated_probability = (
        max(70, triage.replica_probability)
        if confirmed_replica
        else triage.replica_probability
        if has_material_signal
        else min(25, triage.replica_probability)
    )
    headline = (triage.headline_text or "").casefold()
    is_success = "success" in headline or "paid" in headline or "sent" in headline
    return PaymentObservation(
        app_name=triage.app_name or "Unknown",
        app_key=(triage.app_key or "unknown").lower(),
        app_confidence=triage.app_confidence,
        screenshot_kind="payment_success" if is_success else "receipt_or_history",
        readability=triage.readability,
        payment_state="success" if is_success else "unknown",
        fields=ExtractedFields(
            amount=triage.amount,
            transaction_id=triage.transaction_id,
            upi_id=triage.upi_id,
            recipient_name=triage.recipient_name,
            sender_name=triage.sender_name,
            bank_name=triage.bank_name,
            timestamp=triage.timestamp,
            status_text=triage.headline_text,
            transaction_label=triage.transaction_label,
        ),
        tampering_evidence=evidence,
        impossible_inconsistencies=[],
        benign_limitations=triage.benign_explanations
        + [f"Benign interoperability or presentation variant: {item}" for item in filtered_claims],
        content_risk_signals=[],
        authenticity_assessment=assessment,
        fake_probability=calibrated_probability,
        confidence=triage.confidence,
        reasons=triage.reasons,
    )


def _run_replica_triage(
    image_views: list[AnalysisView],
    prompt: str,
    model: str,
    reasoning_effort: str,
    image_detail: str,
    max_output_tokens: int,
) -> ModelPassResult:
    response, triage, latency_ms = _run_typed_model(
        image_views,
        prompt,
        model,
        reasoning_effort,
        "standard",
        ReplicaTriage,
        image_detail,
        max_output_tokens,
    )
    return _model_pass_result(
        response,
        _replica_triage_to_observation(triage),
        model,
        len(image_views),
        latency_ms,
        raw_model_score=triage.replica_probability,
    )


def _normalize_pass_result(
    value: ModelPassResult | PaymentObservation,
    role: str,
    model: str,
    view_count: int,
) -> ModelPassResult:
    # Accept a bare observation to keep the orchestration easy to unit-test and
    # compatible with custom model adapters.
    if isinstance(value, PaymentObservation):
        value = ModelPassResult(
            observation=value,
            model=model,
            view_count=view_count,
            estimated_cost_usd=_estimate_cost_usd(model, 0, 0, 0, 0),
            raw_model_score=value.fake_probability,
        )
    value.observation = _remove_benign_presentation_false_signals(value.observation)
    value.role = role
    return value


_CLOCK_TOKEN_RE = re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d\b")
_PROMOTION_TERMS = (
    " ad ",
    " ads ",
    "ad banner",
    "advertisement",
    "advertising",
    " in-app ad",
    "promo",
    "promotion",
    "cashback",
    "scratch-card",
    "scratch card",
    "reward panel",
)
_LOCAL_EDIT_ARTIFACT_TERMS = (
    "paste boundary",
    "anti-alias",
    "pixel edge",
    "resampling",
    "compression halo",
    "misaligned glyph",
)


def _is_benign_presentation_claim(evidence: VisualEvidence) -> bool:
    """Identify model claims that contradict documented normal app behavior."""
    if evidence.strength == "strong":
        return False
    text = " ".join(
        filter(None, [evidence.description, evidence.location, evidence.observed_text])
    ).casefold()
    times = _CLOCK_TOKEN_RE.findall(text)
    same_clock_time = (
        "status bar" in text
        and ("receipt" in text or "transaction" in text or "payment" in text)
        and len(times) >= 2
        and len(set(times)) == 1
    )
    promotion_only = (
        any(term in text for term in _PROMOTION_TERMS)
        and not any(term in text for term in _LOCAL_EDIT_ARTIFACT_TERMS)
    )
    return same_clock_time or promotion_only


def _remove_benign_presentation_false_signals(
    observation: PaymentObservation,
) -> PaymentObservation:
    """Move normal ad/time observations out of the fraud-evidence channel."""
    kept: list[VisualEvidence] = []
    moved: list[str] = []
    for evidence in observation.tampering_evidence:
        if _is_benign_presentation_claim(evidence):
            moved.append(evidence.description)
        else:
            kept.append(evidence)
    if not moved:
        return observation

    observation.tampering_evidence = kept
    observation.benign_limitations = _unique_strings(
        observation.benign_limitations + moved
    )
    material_evidence = any(
        item.strength in {"moderate", "strong"} for item in kept
    )
    if (
        observation.authenticity_assessment == "uncertain"
        and not material_evidence
        and not observation.impossible_inconsistencies
        and observation.fake_probability <= 55
    ):
        observation.authenticity_assessment = "no_evidence_of_manipulation"
        observation.fake_probability = min(observation.fake_probability, 25)
    return observation


def _summarize_model_usage(passes: list[ModelPassResult]) -> dict:
    known_costs = [
        item.estimated_cost_usd
        for item in passes
        if item.estimated_cost_usd is not None
    ]
    estimated_cost = (
        round(sum(known_costs), 6) if len(known_costs) == len(passes) else None
    )
    return {
        "input_tokens": sum(item.input_tokens for item in passes),
        "cached_input_tokens": sum(item.cached_input_tokens for item in passes),
        "cache_write_tokens": sum(item.cache_write_tokens for item in passes),
        "output_tokens": sum(item.output_tokens for item in passes),
        "reasoning_tokens": sum(item.reasoning_tokens for item in passes),
        "total_tokens": sum(item.total_tokens for item in passes),
        "model_latency_ms": max((item.latency_ms for item in passes), default=0),
        "estimated_cost_usd": estimated_cost,
        "request_estimated_cost_usd": estimated_cost,
        "budget_target_usd": BUDGET_TARGET_USD_PER_CHECK,
        "within_budget": (
            estimated_cost <= BUDGET_TARGET_USD_PER_CHECK
            if estimated_cost is not None
            else None
        ),
        "cache_reused": False,
        "pricing_note": (
            "Estimate from configured standard list prices; "
            "OpenAI billing is authoritative."
        ),
        "passes": [
            {
                "role": item.role,
                "model": item.model,
                "views": item.view_count,
                "input_tokens": item.input_tokens,
                "cached_input_tokens": item.cached_input_tokens,
                "cache_write_tokens": item.cache_write_tokens,
                "output_tokens": item.output_tokens,
                "reasoning_tokens": item.reasoning_tokens,
                "total_tokens": item.total_tokens,
                "estimated_cost_usd": item.estimated_cost_usd,
                "latency_ms": item.latency_ms,
                "app_key": item.observation.app_key,
                "app_confidence": item.observation.app_confidence,
                "authenticity_assessment": item.observation.authenticity_assessment,
                "raw_model_score": item.raw_model_score,
                "fake_probability": item.observation.fake_probability,
                "strong_evidence": sum(
                    evidence.strength == "strong"
                    for evidence in item.observation.tampering_evidence
                ),
                "moderate_evidence": sum(
                    evidence.strength == "moderate"
                    for evidence in item.observation.tampering_evidence
                ),
            }
            for item in passes
        ],
    }


def _needs_review(observation: PaymentObservation) -> bool:
    if REVIEW_MODE in {"off", "false", "0", "disabled"}:
        return False
    if REVIEW_MODE == "always":
        return True
    return any(
        (
            observation.authenticity_assessment != "no_evidence_of_manipulation",
            observation.fake_probability > 25,
            any(
                item.strength in {"moderate", "strong"}
                for item in observation.tampering_evidence
            ),
            bool(observation.impossible_inconsistencies),
            # A partially readable or non-standard receipt is common for genuine
            # apps (for example CRED share cards and Paytm ad-heavy receipts).
            # Review only when the image is actually unreadable; evidence and
            # consistency signals above still escalate suspicious screenshots.
            observation.readability == "unreadable",
            observation.screenshot_kind == "unreadable",
            _has_provider_identifier_review_signal(observation),
            _has_malformed_explicit_transaction_id_review_signal(observation),
            _has_suspicious_success_heading_review_signal(observation),
        )
    )


def _is_clean_observation(observation: PaymentObservation) -> bool:
    material_evidence = any(
        item.strength in {"moderate", "strong"} for item in observation.tampering_evidence
    )
    return all(
        (
            observation.authenticity_assessment == "no_evidence_of_manipulation",
            observation.fake_probability <= 25,
            not material_evidence,
            not observation.impossible_inconsistencies,
            observation.readability != "unreadable",
        )
    )


def _needs_adjudication(observations: list[PaymentObservation]) -> bool:
    if ADJUDICATOR_MODE in {"off", "false", "0", "disabled"}:
        return False
    if ADJUDICATOR_MODE == "always":
        return True
    if not observations:
        return False
    if len(observations) == 1:
        # A clearly clean first pass should be the cheap path. A lone uncertain
        # or fake-looking result still gets an independent attempt.
        return not _is_clean_observation(observations[0])
    required_votes = (len(observations) // 2) + 1
    if sum(_has_confirmed_fake_evidence(item) for item in observations) >= required_votes:
        return False
    if all(_is_clean_observation(item) for item in observations):
        return False
    if all(_has_confirmed_fake_evidence(item) for item in observations):
        return False
    return True


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = " ".join(str(value).split()).strip()
        key = clean.casefold()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result


# PhonePe transaction IDs observed across current and older legitimate receipt
# variants use a short alphabetic provider prefix followed by a long numeric
# payload (for example T... and NX...). Keep this deliberately broad so the
# rule survives new prefixes. UTRs are a different field and are never checked
# against this pattern.
_PROVIDER_TRANSACTION_ID_PATTERNS = {
    "phonepe": re.compile(r"^[A-Z]{1,3}\d{18,30}$"),
}

# These are stable English system-heading errors seen in clone/fake payment
# apps. One OCR read only requests a precision review; it never confirms a
# fake. Promotion requires the exact same normalized heading from two
# independent model passes, which protects legitimate screens from one noisy
# OCR read while catching clean fake-app renders without paste artifacts.
_SUSPICIOUS_SUCCESS_HEADINGS = {
    "payments successful",
    "payment successfull",
    "transaction successfull",
    "payement successful",
    "payment sucessful",
    "transaction sucessful",
    "sent succesfully",
}


def _normalized_app_identity(observation: PaymentObservation) -> str:
    identity = f"{observation.app_key} {observation.app_name}".casefold()
    compact = re.sub(r"[^a-z0-9]+", "", identity)
    if "phonepe" in compact:
        return "phonepe"
    return ""


def _normalized_transaction_id(value: str | None) -> str:
    return re.sub(r"\s+", "", value or "").upper()


def _normalized_status_heading(value: str | None) -> str:
    return re.sub(r"[^a-z]+", " ", (value or "").casefold()).strip()


def _suspicious_success_heading(observation: PaymentObservation) -> str | None:
    heading = _normalized_status_heading(observation.fields.status_text)
    return heading if heading in _SUSPICIOUS_SUCCESS_HEADINGS else None


def _has_suspicious_success_heading_review_signal(
    observation: PaymentObservation,
) -> bool:
    """Escalate a likely system-heading error without trusting one OCR pass."""
    return _suspicious_success_heading(observation) is not None


def _is_explicit_transaction_id_label(value: str | None) -> bool:
    label = re.sub(r"[^a-z0-9]+", " ", (value or "").casefold()).strip()
    return (
        "transaction" in label
        and "id" in label.split()
        and "utr" not in label
        and "reference" not in label
    )


def _provider_identifier_candidate(
    observation: PaymentObservation,
) -> tuple[str, str] | None:
    provider = _normalized_app_identity(observation)
    pattern = _PROVIDER_TRANSACTION_ID_PATTERNS.get(provider)
    transaction_id = _normalized_transaction_id(observation.fields.transaction_id)
    if (
        not pattern
        or observation.app_confidence < 75
        or not _is_explicit_transaction_id_label(observation.fields.transaction_label)
        or not transaction_id
        or pattern.fullmatch(transaction_id)
    ):
        return None
    return provider, transaction_id


def _has_provider_identifier_review_signal(observation: PaymentObservation) -> bool:
    """Escalate one suspicious read, but never confirm it on one read alone."""
    return _provider_identifier_candidate(observation) is not None


def _has_malformed_explicit_transaction_id_review_signal(
    observation: PaymentObservation,
) -> bool:
    """Review a conspicuously short mixed ID without treating it as proof."""
    if not _is_explicit_transaction_id_label(observation.fields.transaction_label):
        return False
    transaction_id = _normalized_transaction_id(observation.fields.transaction_id)
    return (
        bool(transaction_id)
        and len(transaction_id) < 14
        and any(character.isalpha() for character in transaction_id)
        and any(character.isdigit() for character in transaction_id)
    )


def _apply_provider_identifier_consensus(
    observations: list[PaymentObservation],
) -> bool:
    """Promote a repeated provider-ID conflict into consensus evidence.

    A single model report can be an OCR mistake. Confirmation therefore needs
    the same explicit transaction-ID value from at least two independent model
    passes, plus high-confidence provider identification in at least one pass.
    """
    high_confidence_providers = {
        provider
        for observation in observations
        if observation.app_confidence >= 75
        if (provider := _normalized_app_identity(observation))
    }
    candidates: list[tuple[str, str, PaymentObservation]] = []
    for observation in observations:
        if not _is_explicit_transaction_id_label(observation.fields.transaction_label):
            continue
        transaction_id = _normalized_transaction_id(observation.fields.transaction_id)
        if not transaction_id:
            continue
        for provider in high_confidence_providers:
            pattern = _PROVIDER_TRANSACTION_ID_PATTERNS.get(provider)
            if pattern and not pattern.fullmatch(transaction_id):
                candidates.append((provider, transaction_id, observation))

    repeated = {
        item
        for item, count in Counter(
            (provider, transaction_id) for provider, transaction_id, _ in candidates
        ).items()
        if count >= 2
    }
    if not repeated:
        return False

    applied = False
    for provider, transaction_id in sorted(repeated):
        description = (
            "Two independent reads found the same explicit "
            f"{provider.title()} transaction ID, but its structure conflicts "
            "with the provider-specific identifier family."
        )
        for candidate_provider, candidate_id, observation in candidates:
            if (candidate_provider, candidate_id) != (provider, transaction_id):
                continue
            if not any(
                item.category == "transaction_data"
                and item.strength == "strong"
                and item.observed_text == transaction_id
                for item in observation.tampering_evidence
            ):
                observation.tampering_evidence.append(
                    VisualEvidence(
                        category="transaction_data",
                        strength="strong",
                        description=description,
                        location="transaction details",
                        observed_text=transaction_id,
                    )
                )
            observation.authenticity_assessment = "clear_manipulation"
            observation.fake_probability = max(observation.fake_probability, 82)
            observation.reasons = _unique_strings(observation.reasons + [description])
            applied = True
    return applied


def _apply_success_heading_consensus(
    observations: list[PaymentObservation],
) -> bool:
    """Confirm a stable fake-app heading only after two independent reads."""
    candidates = [
        (heading, observation)
        for observation in observations
        if (heading := _suspicious_success_heading(observation))
    ]
    repeated = {
        heading
        for heading, count in Counter(heading for heading, _ in candidates).items()
        if count >= 2
    }
    if not repeated:
        return False

    applied = False
    for heading in sorted(repeated):
        description = (
            "Two independent reads confirmed the same grammatically invalid "
            f'payment-system success heading: "{heading}".'
        )
        for candidate_heading, observation in candidates:
            if candidate_heading != heading:
                continue
            if not any(
                item.category == "replica_app"
                and item.strength == "strong"
                and _normalized_status_heading(item.observed_text) == heading
                for item in observation.tampering_evidence
            ):
                observation.tampering_evidence.append(
                    VisualEvidence(
                        category="replica_app",
                        strength="strong",
                        description=description,
                        location="payment success heading",
                        observed_text=observation.fields.status_text,
                    )
                )
            observation.authenticity_assessment = "clear_manipulation"
            observation.fake_probability = max(observation.fake_probability, 82)
            observation.reasons = _unique_strings(observation.reasons + [description])
            applied = True
    return applied


def _needs_precision_review(observations: list[PaymentObservation]) -> bool:
    return any(
        _has_malformed_explicit_transaction_id_review_signal(observation)
        or _has_confirmed_fake_evidence(observation)
        or bool(observation.impossible_inconsistencies)
        or _has_non_heading_material_evidence(observation)
        for observation in observations
    )


def _has_non_heading_material_evidence(observation: PaymentObservation) -> bool:
    """Keep heading-only OCR confirmation on Nano; other evidence uses Mini."""
    heading = _suspicious_success_heading(observation)
    for evidence in observation.tampering_evidence:
        if evidence.strength not in {"moderate", "strong"}:
            continue
        evidence_text = _normalized_status_heading(
            " ".join(
                filter(
                    None,
                    [evidence.observed_text, evidence.description],
                )
            )
        )
        if not heading or heading not in evidence_text:
            return True
    return False


def _candidate_signal_suffix(observations: list[PaymentObservation]) -> str:
    candidate_signals = _unique_strings(
        [
            item.description
            for observation in observations
            for item in observation.tampering_evidence
            if item.strength in {"moderate", "strong"}
        ]
        + [
            f'Exact system heading "{observation.fields.status_text}" may contain a stable grammar or spelling error.'
            for observation in observations
            if _has_suspicious_success_heading_review_signal(observation)
        ]
    )[:6]
    if not candidate_signals:
        return ""
    return (
        "\n\nCandidate signals to verify or reject independently:\n- "
        + "\n- ".join(candidate_signals)
        + "\nDo not accept these claims unless the corresponding pixels are visible."
    )


def _merge_fields(observations: list[PaymentObservation]) -> ExtractedFields:
    merged: dict[str, str | None] = {}
    for field_name in ExtractedFields.model_fields:
        candidates = [getattr(item.fields, field_name) for item in observations]
        merged[field_name] = next((value for value in candidates if value), None)
    return ExtractedFields(**merged)


def _has_confirmed_fake_evidence(observation: PaymentObservation) -> bool:
    strong_count = sum(item.strength == "strong" for item in observation.tampering_evidence)
    return (
        observation.authenticity_assessment == "clear_manipulation"
        and (strong_count > 0 or bool(observation.impossible_inconsistencies))
        and observation.fake_probability >= 65
    )


def calibrate_observations(observations: list[PaymentObservation]) -> dict:
    """Turn independent observations into an evidence-gated public verdict."""
    if not observations:
        raise ValueError("At least one forensic observation is required.")

    evidence = [item for obs in observations for item in obs.tampering_evidence]
    strong_count = sum(item.strength == "strong" for item in evidence)
    moderate_count = sum(item.strength == "moderate" for item in evidence)
    impossible = _unique_strings(
        [item for obs in observations for item in obs.impossible_inconsistencies]
    )
    probabilities = [obs.fake_probability for obs in observations]
    average_probability = round(mean(probabilities))
    confirmed_votes = sum(_has_confirmed_fake_evidence(obs) for obs in observations)
    clean_votes = sum(_is_clean_observation(obs) for obs in observations)
    required_votes = 1 if len(observations) == 1 else (len(observations) // 2) + 1
    replica_moderate_count = sum(
        item.category == "replica_app" and item.strength == "moderate" for item in evidence
    )
    confirmed_fake = confirmed_votes >= required_votes
    credible_dissent = bool(
        confirmed_votes
        or strong_count
        or impossible
        or replica_moderate_count
        or moderate_count >= 2
    )

    if confirmed_fake:
        verdict = "SCAM"
        risk = min(98, max(70, average_probability))
    elif clean_votes >= required_votes and not credible_dissent and average_probability <= 30:
        verdict = "SAFE"
        risk = min(30, max(5, average_probability))
    else:
        verdict = "SUSPICIOUS"
        risk = min(69, max(31, average_probability))

    best_app = max(observations, key=lambda item: item.app_confidence)
    fields = _merge_fields(observations)
    limitations = _unique_strings(
        [item for obs in observations for item in obs.benign_limitations]
    )
    content_risk = _unique_strings(
        [item for obs in observations for item in obs.content_risk_signals]
    )

    if verdict == "SCAM":
        reason_text = _unique_strings(
            [item.description for item in evidence if item.strength == "strong"] + impossible
        )
    elif verdict == "SUSPICIOUS":
        reason_text = _unique_strings(
            [item.description for item in evidence if item.strength != "weak"]
            + impossible
            + ["The available visual evidence is not conclusive enough for a genuine or fake verdict."]
        )
    else:
        review_wording = (
            "The review found"
            if len(observations) == 1
            else "The independent reviews found"
        )
        reason_text = [
            f"{review_wording} no clear, specific evidence of screenshot fabrication or editing."
        ]

    why = [{"en": item, "hi": ""} for item in reason_text[:6]]
    visual_forensics = [
        {
            "en": item.description,
            "hi": "",
            "strength": item.strength,
            "category": item.category,
            "location": item.location,
        }
        for item in evidence[:10]
    ]

    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    confidence = min(observations, key=lambda item: confidence_rank[item.confidence]).confidence
    if len(observations) > 1 and len({obs.authenticity_assessment for obs in observations}) > 1:
        confidence = "low"

    return {
        "verdict": verdict,
        "risk_percentage": risk,
        "confidence": confidence,
        "verdict_label": VERDICT_LABELS[verdict],
        "detected_app": {
            "name": best_app.app_name or "Unknown",
            "app_key": (best_app.app_key or "unknown").lower(),
            "detection_confidence": best_app.app_confidence,
        },
        "extracted_fields": fields.model_dump(),
        "payment_state": observations[0].payment_state,
        "screenshot_kind": observations[0].screenshot_kind,
        "why": why,
        "reasons": why,
        "visual_forensics": visual_forensics,
        "visual_signals": visual_forensics,
        "benign_limitations": limitations[:8],
        "content_risk_signals": content_risk[:8],
        "evidence_summary": {
            "strong": strong_count,
            "moderate": moderate_count,
            "weak": sum(item.strength == "weak" for item in evidence),
            "replica_app_moderate": replica_moderate_count,
            "impossible_inconsistencies": len(impossible),
            "review_count": len(observations),
            "clean_votes": clean_votes,
            "confirmed_fake_votes": confirmed_votes,
            "required_consensus_votes": required_votes,
        },
        "pattern_match": {
            "found": bool(strong_count or impossible),
            "match_count": strong_count + len(impossible),
        },
        "what_to_do": WHAT_TO_DO[verdict],
        "how_to_avoid": HOW_TO_AVOID,
    }


def _forensic_logic_score(
    result: dict,
    local_forensics: LocalForensicsResult,
) -> int:
    """Build the deterministic 25% component from auditable evidence.

    The score is continuous and additive rather than a verdict lookup table.
    Exact known-fake signatures never reach this path because they short-circuit
    before the paid model call.
    """
    summary = result.get("evidence_summary") or {}
    weak = max(0, int(summary.get("weak", 0)))
    moderate = max(0, int(summary.get("moderate", 0)))
    strong = max(0, int(summary.get("strong", 0)))
    impossible = max(0, int(summary.get("impossible_inconsistencies", 0)))
    replica_moderate = max(0, int(summary.get("replica_app_moderate", 0)))

    score = 6.0
    score += min(10.0, weak * 2.5)
    score += min(42.0, moderate * 14.0)
    score += min(56.0, strong * 28.0)
    score += min(40.0, impossible * 20.0)
    score += min(12.0, replica_moderate * 4.0)

    if local_forensics.attention_overlay_candidate:
        score += min(
            14.0,
            4.0 + local_forensics.attention_overlay_area_ratio * 220.0,
        )
    if local_forensics.red_overlay_candidate:
        score += min(
            20.0,
            7.0 + local_forensics.red_overlay_area_ratio * 260.0,
        )

    annotation_term = (
        local_forensics.annotation_overlay_term
        or (
            _model_confirmed_annotation_term(result)
            if local_forensics.attention_overlay_candidate
            else None
        )
    )
    if annotation_term:
        score = max(score, 82.0)
    elif local_forensics.force_review:
        score = max(score, 46.0)

    clean_votes = max(0, int(summary.get("clean_votes", 0)))
    if not any((weak, moderate, strong, impossible, annotation_term)):
        score -= min(4.0, clean_votes * 1.5)
    return max(0, min(100, round(score)))


def _apply_weighted_ensemble(
    result: dict,
    model_passes: list[ModelPassResult],
    local_forensics: LocalForensicsResult,
) -> None:
    """Apply the product's explicit 75% vision / 25% forensic blend."""
    if not model_passes:
        return
    observations = [item.observation for item in model_passes]
    raw_scores = [
        item.raw_model_score
        if item.raw_model_score is not None
        else item.observation.fake_probability
        for item in model_passes
    ]
    model_scores = [
        _category_consistent_model_score(raw_score, item.observation)
        for raw_score, item in zip(raw_scores, model_passes)
    ]
    model_score = round(mean(model_scores), 1)
    forensic_score = _forensic_logic_score(result, local_forensics)
    combined_score = round(
        model_score * MODEL_SCORE_WEIGHT
        + forensic_score * FORENSIC_SCORE_WEIGHT
    )
    combined_score = max(0, min(100, combined_score))

    # A screenshot that cannot be read, or materially different GPT reads, is
    # inherently inconclusive even when their arithmetic average is low.
    if any(item.readability == "unreadable" for item in observations):
        combined_score = max(SAFE_MAX_SCORE + 1, combined_score)
    if len(model_scores) > 1 and max(model_scores) - min(model_scores) >= 30:
        combined_score = max(SAFE_MAX_SCORE + 1, combined_score)

    if combined_score >= SCAM_MIN_SCORE:
        verdict = "SCAM"
    elif combined_score > SAFE_MAX_SCORE:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    disagreement = abs(model_score - forensic_score)
    threshold_distance = min(
        abs(combined_score - SAFE_MAX_SCORE),
        abs(combined_score - SCAM_MIN_SCORE),
    )
    confidence = (
        "low"
        if disagreement >= 35 or threshold_distance <= 5
        else "high"
        if disagreement <= 18 and threshold_distance >= 15
        else "medium"
    )

    result.update(
        {
            "verdict": verdict,
            "risk_percentage": combined_score,
            "safety_percentage": 100 - combined_score,
            "confidence": confidence,
            "verdict_label": VERDICT_LABELS[verdict],
            "what_to_do": WHAT_TO_DO[verdict],
            "weighted_ensemble": {
                "model_score": model_score,
                "forensic_score": forensic_score,
                "model_weight": MODEL_SCORE_WEIGHT,
                "forensic_weight": FORENSIC_SCORE_WEIGHT,
                "combined_score": combined_score,
                "model_passes": len(model_passes),
                "model_scores": model_scores,
                "raw_model_scores": raw_scores,
                "score_disagreement": round(disagreement, 1),
            },
        }
    )


def _category_consistent_model_score(
    raw_score: int | float,
    observation: PaymentObservation,
) -> int:
    """Make the model's numeric score agree with its own categorical verdict.

    Structured-output models can occasionally say "likely genuine" while also
    emitting a suspicious-range number.  The category remains a GPT judgement,
    so bounding the number to that category prevents contradictory UI without
    replacing the score with a fixed bucket value.
    """
    score = max(0, min(100, round(float(raw_score))))
    if observation.authenticity_assessment == "no_evidence_of_manipulation":
        return min(SAFE_MAX_SCORE, score)
    if observation.authenticity_assessment == "uncertain":
        return min(SCAM_MIN_SCORE - 1, max(SAFE_MAX_SCORE + 1, score))
    return max(SCAM_MIN_SCORE, score)


def _sync_score_metadata(
    result: dict,
    local_forensics: LocalForensicsResult | None = None,
) -> None:
    """Expose an honest, frontend-ready 0-100 evidence indicator.

    The legacy percentage keys remain for API compatibility, but this is not a
    calibrated probability that a bank transfer settled. The UI can use the
    explicit indicator fields without presenting false statistical precision.
    """
    risk = max(0, min(100, int(result.get("risk_percentage", 0))))
    safety = 100 - risk
    result["risk_percentage"] = risk
    result["safety_percentage"] = safety
    summary = result.get("evidence_summary") or {}
    annotation_term = (
        local_forensics.annotation_overlay_term if local_forensics else None
    )
    if (
        annotation_term is None
        and local_forensics
        and local_forensics.attention_overlay_candidate
    ):
        annotation_term = _model_confirmed_annotation_term(result)
    weighted = result.get("weighted_ensemble") or {}
    known_fake_match = bool(
        local_forensics and local_forensics.known_fake is not None
    )
    result["score_breakdown"] = {
        "risk_indicator": risk,
        "safety_indicator": safety,
        "scale": "0-100 evidence indicator",
        "method": (
            "known_fake_signature"
            if known_fake_match
            else "gpt_75_forensics_25_v1"
        ),
        "is_calibrated_probability": False,
        "interpretation": (
            "Visual screenshot evidence only; this does not verify bank settlement."
        ),
        "components": {
            "gpt_vision": {
                "score": weighted.get("model_score"),
                "weight": weighted.get("model_weight", 0 if known_fake_match else None),
            },
            "forensic_logic": {
                "score": weighted.get("forensic_score", risk if known_fake_match else None),
                "weight": weighted.get(
                    "forensic_weight", 1 if known_fake_match else None
                ),
            },
            "combined_score": weighted.get("combined_score", risk),
        },
        "signals": {
            "strong": int(summary.get("strong", 0)),
            "moderate": int(summary.get("moderate", 0)),
            "weak": int(summary.get("weak", 0)),
            "known_fake_match": known_fake_match,
            "annotation_overlay": bool(annotation_term),
            "annotation_term": annotation_term,
        },
    }


def _known_fake_result(
    local_forensics: LocalForensicsResult,
    dimensions: tuple[int, int],
) -> dict:
    """Return a complete zero-token result for a confirmed fake signature."""
    match = local_forensics.known_fake
    if match is None:  # pragma: no cover - guarded by the caller
        raise ValueError("Known-fake result requested without a signature match")

    risk = 99 if match.method == "exact_sha256" else 96
    reason = (
        "This image matches a confirmed fake-payment screenshot signature "
        f"({match.family}) using {match.method.replace('_', ' ')}."
    )
    visual_forensics = [
        {
            "en": reason,
            "hi": "",
            "strength": "strong",
            "category": "replica_app",
            "location": "whole screenshot",
        }
    ]
    why = [{"en": reason, "hi": ""}]
    result = {
        "verdict": "SCAM",
        "risk_percentage": risk,
        "safety_percentage": 100 - risk,
        "confidence": "high",
        "verdict_label": VERDICT_LABELS["SCAM"],
        "detected_app": {
            "name": match.app_name,
            "app_key": match.app_key,
            "detection_confidence": 95,
        },
        "extracted_fields": ExtractedFields(
            amount=None,
            transaction_id=None,
            upi_id=None,
            recipient_name=None,
            sender_name=None,
            bank_name=None,
            timestamp=None,
            status_text=None,
            transaction_label=None,
        ).model_dump(),
        "payment_state": "unknown",
        "screenshot_kind": "payment_success",
        "why": why,
        "reasons": why,
        "visual_forensics": visual_forensics,
        "visual_signals": visual_forensics,
        "benign_limitations": [],
        "content_risk_signals": [],
        "evidence_summary": {
            "strong": 1,
            "moderate": 0,
            "weak": 0,
            "replica_app_moderate": 0,
            "impossible_inconsistencies": 0,
            "review_count": 0,
            "clean_votes": 0,
            "confirmed_fake_votes": 1,
            "required_consensus_votes": 1,
        },
        "pattern_match": {"found": True, "match_count": 1},
        "what_to_do": WHAT_TO_DO["SCAM"],
        "how_to_avoid": HOW_TO_AVOID,
        "analysis_version": ANALYSIS_VERSION,
        "review_performed": False,
        "review_status": "not_required",
        "ensemble": {
            "attempted_passes": 0,
            "successful_passes": 0,
            "failed_passes": 0,
            "adjudicator_performed": False,
            "analysis_views": 0,
            "view_counts": {},
            "cascade_path": ["local_known_fake"],
        },
        "model_usage": {
            **_summarize_model_usage([]),
            "analysis_latency_ms": local_forensics.latency_ms,
        },
        "image_dimensions": {"width": dimensions[0], "height": dimensions[1]},
        "local_forensics": local_forensics.telemetry(),
    }
    _sync_score_metadata(result, local_forensics)
    return result


def _apply_local_overlay_floor(
    result: dict,
    local_forensics: LocalForensicsResult,
) -> None:
    """Keep a materially annotated screenshot from being called clean/safe."""
    model_annotation_term = None
    if local_forensics.attention_overlay_candidate:
        model_annotation_term = _model_confirmed_annotation_term(result)
    has_confirmed_overlay = (
        local_forensics.needs_overlay_floor or model_annotation_term is not None
    )
    if not has_confirmed_overlay or result.get("verdict") == "SCAM":
        return

    annotation_term = (
        local_forensics.annotation_overlay_term or model_annotation_term
    )
    if annotation_term and annotation_term != "model-confirmed annotation":
        floor = 68
        reason = (
            f'Third-party warning text ("{annotation_term}") overlaps the receipt '
            "controls. The submitted image is annotated/edited and cannot be "
            "accepted as clean payment proof, although this alone does not prove "
            "the underlying bank transaction was fabricated."
        )
        location = "annotation over receipt controls"
    elif annotation_term:
        floor = 68
        reason = (
            "A prominent third-party annotation overlaps the receipt controls. "
            "The submitted image is edited/annotated and cannot be accepted as "
            "clean payment proof, although this alone does not prove the underlying "
            "bank transaction was fabricated."
        )
        location = "annotation over receipt controls"
    else:
        floor = 58
        reason = (
            "A large saturated-red graphic overlaps the upper payment area. The "
            "result is inconclusive until the overlay text and original transaction "
            "are independently verified."
        )
        location = "upper/central payment area"
    if result.get("verdict") == "SAFE":
        result.update(
            {
                "verdict": "SUSPICIOUS",
                "risk_percentage": floor,
                "confidence": "low",
                "verdict_label": VERDICT_LABELS["SUSPICIOUS"],
                "what_to_do": WHAT_TO_DO["SUSPICIOUS"],
            }
        )
    else:
        result["risk_percentage"] = max(
            floor, int(result.get("risk_percentage", 0))
        )

    result.setdefault("why", []).append({"en": reason, "hi": ""})
    result["reasons"] = result["why"]
    evidence = {
        "en": reason,
        "hi": "",
        "strength": "moderate",
        "category": "overlay",
        "location": location,
    }
    result.setdefault("visual_forensics", []).append(evidence)
    result["visual_signals"] = result["visual_forensics"]
    summary = result.setdefault("evidence_summary", {})
    summary["moderate"] = int(summary.get("moderate", 0)) + 1
    result["pattern_match"] = {
        "found": True,
        "match_count": int(result.get("pattern_match", {}).get("match_count", 0)) + 1,
    }


def _model_confirmed_annotation_term(result: dict) -> str | None:
    """Corroborate an attention-color candidate with localized model evidence.

    This fallback is deliberately conjunctive: pixels must first contain a
    prominent red/magenta component, and the model must then localize it as an
    overlay/annotation over the receipt. Ordinary red branding, app promotions
    and ads are explicitly excluded. An explicit warning/fabrication word is
    returned when available, but low-resolution OCR is not required.
    """
    overlay_markers = (
        "overlay",
        "overlaid",
        "annotation",
        "handwritten",
        "warning text",
        "covering the receipt",
        "covers the receipt",
        "covering receipt",
    )
    for evidence in result.get("visual_forensics") or []:
        if not isinstance(evidence, dict):
            continue
        description = str(evidence.get("en") or "")
        normalized = " ".join(description.casefold().split())
        if not any(marker in normalized for marker in overlay_markers):
            continue
        location = str(evidence.get("location") or "").casefold()
        benign_markers = ("advert", "promo", "reward", "banner", "offer")
        if any(marker in location for marker in benign_markers):
            continue
        if term := _explicit_overlay_term(description):
            return term
        if any(marker in normalized for marker in benign_markers):
            continue
        return "model-confirmed annotation"
    return None


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    analysis_started_at = time.perf_counter()
    prepared_bytes, media_type, dimensions = _prepare_image(image_bytes)
    local_forensics = analyze_local_forensics(prepared_bytes)
    if local_forensics.known_fake is not None:
        return _known_fake_result(local_forensics, dimensions)

    local_prompt_suffix = local_forensics.prompt_suffix()
    loop = asyncio.get_running_loop()
    observations: list[PaymentObservation] = []
    model_passes: list[ModelPassResult] = []
    failures: list[Exception] = []
    attempted_passes = 0
    attempted_view_counts: dict[str, int] = {}
    review_disabled = REVIEW_MODE in {"off", "false", "0", "disabled"}
    view_cache: dict[int, list[AnalysisView]] = {}

    def get_views(limit: int) -> list[AnalysisView]:
        if limit not in view_cache:
            view_cache[limit] = _make_analysis_views(
                prepared_bytes,
                media_type,
                max_views=limit,
            )
        return view_cache[limit]

    async def execute_pass(
        role: str,
        image_views: list[AnalysisView],
        prompt: str,
        model: str,
        effort: str,
        mode: str = "standard",
    ) -> ModelPassResult:
        raw_result = await loop.run_in_executor(
            None,
            _run_model,
            image_views,
            prompt,
            model,
            effort,
            mode,
        )
        return _normalize_pass_result(
            raw_result,
            role,
            model,
            len(image_views),
        )

    async def execute_replica_triage(
        role: str,
        image_views: list[AnalysisView],
        prompt: str,
        model: str,
        effort: str,
        detail: str,
        max_output_tokens: int,
    ) -> ModelPassResult:
        raw_result = await loop.run_in_executor(
            None,
            _run_replica_triage,
            image_views,
            prompt,
            model,
            effort,
            detail,
            max_output_tokens,
        )
        return _normalize_pass_result(
            raw_result,
            role,
            model,
            len(image_views),
        )

    primary_views = get_views(PRIMARY_MAX_ANALYSIS_VIEWS)
    attempted_passes += 1
    attempted_view_counts["primary"] = len(primary_views)
    initial_tasks = [
        execute_replica_triage(
            "primary",
            primary_views,
            REPLICA_TRIAGE_PROMPT + local_prompt_suffix,
            PRIMARY_MODEL,
            PRIMARY_REASONING_EFFORT,
            _normalize_image_detail(PRIMARY_IMAGE_DETAIL, "low"),
            REPLICA_MAX_OUTPUT_TOKENS,
        )
    ]
    if REVIEW_MODE == "always":
        review_views = get_views(REVIEW_MAX_ANALYSIS_VIEWS)
        attempted_passes += 1
        attempted_view_counts["review"] = len(review_views)
        initial_tasks.append(
            execute_replica_triage(
                "review",
                review_views,
                (
                    f"{REPLICA_TRIAGE_PROMPT}\n\n{REPLICA_REVIEW_PROMPT}"
                    + local_prompt_suffix
                ),
                REVIEW_MODEL,
                REVIEW_REASONING_EFFORT,
                _normalize_image_detail(REVIEW_IMAGE_DETAIL, "auto"),
                REVIEW_MAX_OUTPUT_TOKENS,
            )
        )

    initial_results = await asyncio.gather(
        *initial_tasks,
        return_exceptions=True,
    )
    for item in initial_results:
        if isinstance(item, BaseException):
            logger.warning("Payment screenshot fast ensemble pass failed: %s", item)
            failures.append(item if isinstance(item, Exception) else RuntimeError(str(item)))
        else:
            model_passes.append(item)
            observations.append(item.observation)

    if REVIEW_MODE != "always":
        review_required = not review_disabled and (
            not observations
            or local_forensics.force_review
            or any(_needs_review(item) for item in observations)
        )
        if review_required:
            review_views = get_views(REVIEW_MAX_ANALYSIS_VIEWS)
            attempted_passes += 1
            attempted_view_counts["review"] = len(review_views)
            precision_review = (
                local_forensics.force_review
                or _needs_precision_review(observations)
            )
            selected_review_model = REVIEW_MODEL if precision_review else CHEAP_REVIEW_MODEL
            selected_review_effort = (
                REVIEW_REASONING_EFFORT
                if precision_review
                else CHEAP_REVIEW_REASONING_EFFORT
            )
            selected_review_tokens = (
                REVIEW_MAX_OUTPUT_TOKENS
                if precision_review
                else CHEAP_REVIEW_MAX_OUTPUT_TOKENS
            )
            review_prompt = (
                f"{REPLICA_TRIAGE_PROMPT}\n\n{REPLICA_REVIEW_PROMPT}"
                + _candidate_signal_suffix(observations)
                + local_prompt_suffix
            )
            try:
                review_pass = await execute_replica_triage(
                    "review",
                    review_views,
                    review_prompt,
                    selected_review_model,
                    selected_review_effort,
                    _normalize_image_detail(REVIEW_IMAGE_DETAIL, "auto"),
                    selected_review_tokens,
                )
                model_passes.append(review_pass)
                observations.append(review_pass.observation)
            except Exception as exc:
                logger.warning("Payment screenshot replica-review pass failed: %s", exc)
                failures.append(exc)

    _apply_provider_identifier_consensus(observations)
    _apply_success_heading_consensus(observations)
    for model_pass in model_passes:
        if (
            model_pass.observation.authenticity_assessment == "clear_manipulation"
            and model_pass.observation.fake_probability >= SCAM_MIN_SCORE
        ):
            model_pass.raw_model_score = max(
                model_pass.raw_model_score or 0,
                model_pass.observation.fake_probability,
            )

    adjudicator_performed = False
    if not review_disabled and observations and _needs_adjudication(observations):
        adjudicator_views = get_views(ADJUDICATOR_MAX_ANALYSIS_VIEWS)
        attempted_passes += 1
        attempted_view_counts["adjudicator"] = len(adjudicator_views)
        adjudicator_performed = True
        adjudicator_prompt = (
            ADJUDICATOR_PROMPT
            + _candidate_signal_suffix(observations)
            + local_prompt_suffix
        )
        try:
            adjudicator_pass = await execute_pass(
                "adjudicator",
                adjudicator_views,
                adjudicator_prompt,
                ADJUDICATOR_MODEL,
                ADJUDICATOR_REASONING_EFFORT,
                ADJUDICATOR_REASONING_MODE,
            )
            model_passes.append(adjudicator_pass)
            observations.append(adjudicator_pass.observation)
        except Exception as exc:
            logger.warning("Payment screenshot adjudicator pass failed: %s", exc)
            failures.append(exc)

    if not observations:
        raise RuntimeError("All payment screenshot forensic passes failed") from failures[0]

    result = calibrate_observations(observations)
    _apply_local_overlay_floor(result, local_forensics)
    _apply_weighted_ensemble(result, model_passes, local_forensics)
    if failures and result["verdict"] == "SCAM":
        # A required reviewer/adjudicator failure cannot leave a single-pass
        # high-risk decision looking fully confirmed.
        result.update(
            {
                "verdict": "SUSPICIOUS",
                "risk_percentage": 69,
                "safety_percentage": 31,
                "confidence": "low",
                "verdict_label": VERDICT_LABELS["SUSPICIOUS"],
                "what_to_do": WHAT_TO_DO["SUSPICIOUS"],
            }
        )
        if result.get("weighted_ensemble"):
            result["weighted_ensemble"]["combined_score"] = 69
        result.setdefault("why", []).append(
            {
                "en": "A required independent forensic pass failed, so the high-risk result remains unconfirmed.",
                "hi": "",
            }
        )
        result["reasons"] = result["why"]
    if failures:
        result["confidence"] = "low"
    analysis_latency_ms = round((time.perf_counter() - analysis_started_at) * 1000)
    model_usage = _summarize_model_usage(model_passes)
    model_usage["analysis_latency_ms"] = analysis_latency_ms
    review_performed = "review" in attempted_view_counts
    review_succeeded = any(item.role == "review" for item in model_passes)
    result.update(
        {
            "analysis_version": ANALYSIS_VERSION,
            "review_performed": review_performed,
            "review_status": (
                "failed"
                if review_performed and not review_succeeded
                else "completed"
                if review_performed
                else "not_required"
            ),
            "ensemble": {
                "attempted_passes": attempted_passes,
                "successful_passes": len(observations),
                "failed_passes": len(failures),
                "adjudicator_performed": adjudicator_performed,
                "analysis_views": max(attempted_view_counts.values(), default=0),
                "view_counts": attempted_view_counts,
                "cascade_path": [item.role for item in model_passes],
            },
            "model_usage": model_usage,
            "image_dimensions": {"width": dimensions[0], "height": dimensions[1]},
            "local_forensics": local_forensics.telemetry(),
        }
    )
    _sync_score_metadata(result, local_forensics)
    return result
