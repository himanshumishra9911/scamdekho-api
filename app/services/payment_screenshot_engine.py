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
import time
from dataclasses import dataclass
from statistics import mean
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field

try:
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover - dependency is present in production
    pass

load_dotenv()
logger = logging.getLogger(__name__)

ANALYSIS_VERSION = "payment-vision-v11"
PRIMARY_MODEL = os.getenv("PAYMENT_SCREENSHOT_MODEL", "gpt-5.4-nano")
REPLICA_MODEL = os.getenv("PAYMENT_SCREENSHOT_REPLICA_MODEL", PRIMARY_MODEL)
REVIEW_MODEL = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODEL", "gpt-5.4-mini")
ADJUDICATOR_MODEL = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODEL", "gpt-5.6-luna")
REVIEW_MODE = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODE", "suspicious").strip().lower()
ADJUDICATOR_MODE = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODE", "adaptive").strip().lower()
BASE_REASONING_EFFORT = os.getenv("PAYMENT_SCREENSHOT_REASONING_EFFORT", "none")
PRIMARY_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_PRIMARY_REASONING_EFFORT", BASE_REASONING_EFFORT
)
REPLICA_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_REPLICA_REASONING_EFFORT", "none"
)
REVIEW_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_REVIEW_REASONING_EFFORT", "low"
)
ADJUDICATOR_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_EFFORT", "medium"
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
REPLICA_MAX_OUTPUT_TOKENS = int(os.getenv("PAYMENT_SCREENSHOT_REPLICA_MAX_OUTPUT_TOKENS", "1100"))
REVIEW_MAX_OUTPUT_TOKENS = int(os.getenv("PAYMENT_SCREENSHOT_REVIEW_MAX_OUTPUT_TOKENS", "1500"))
ADJUDICATOR_MAX_OUTPUT_TOKENS = int(
    os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MAX_OUTPUT_TOKENS", "1800")
)
BUDGET_TARGET_USD_PER_CHECK = float(
    os.getenv("PAYMENT_SCREENSHOT_BUDGET_TARGET_USD", "0.0012")
)

# Standard API prices per one million tokens. These values are used only for
# request telemetry; billing remains authoritative in the OpenAI dashboard.
MODEL_PRICING_USD_PER_MTOK = {
    "gpt-5-nano": {"input": 0.05, "cached_input": 0.005, "output": 0.4},
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


SYSTEM_PROMPT = """You assess whether an Indian payment screenshot was fabricated or edited. This includes a coherent screen rendered by a fake or clone payment app, not only a pasted value in a real-app screenshot.

The task is screenshot authenticity, not confirmation that money reached an account. A visually genuine screenshot can still show a failed, pending, requested, reversed, old, or fraudulent transaction. Record those facts separately.

Use only visible evidence. Payment app layouts change by app version, OS, language, theme, device size, account type, merchant flow, and A/B test. Unknown or regional apps are normal. Never invent an official layout from memory.

These are NOT tampering evidence by themselves: crop; compression; blur; missing status bar; missing UPI ID, bank, sender, reference number, date, or time; a non-12-digit or alphanumeric reference; old or future date; dark mode; unusual font caused by OS accessibility; cross-app UPI handles or branding; merchant handles; suspicious words in a name or UPI ID; or a simple/clean design.

Treat normal presentation variants as benign unless there is independent, localized evidence of editing. Examples include masked identifiers, decorative receipts, minimal share receipts, large black or white viewer margins, OS/share-sheet chrome, ads, cashback or rewards panels, and receipts embedded inside another app or image viewer. A full transaction page and a shared receipt for the same payment can look substantially different. The status-bar time may reflect when the receipt was viewed rather than when the payment happened.

Strong evidence must be specific and visible, such as a localized paste boundary, inconsistent anti-aliasing around an edited value, an impossible internal contradiction visible in two fields, or a clearly composited logo/status element. Name its location. If a benign explanation is plausible, use weak/moderate evidence or no evidence.

A fake-app screen may be internally clean and have no paste boundary. Consider replica_app evidence only when at least two independent, visible inconsistencies occur inside the payment UI, for example a stable grammatical error in a system heading plus mixed branding/component styles, or mutually incompatible app identity elements. A single typo, unfamiliar layout, missing transaction details, absent reference number, or the recipient saying money was not received is not enough. Use moderate replica_app evidence and uncertain when the combination is concerning but not decisive; use strong only when the visible combination has no plausible app-version, theme, language, accessibility, crop, compression, or OCR explanation.

Do not overcorrect this rule by ignoring transaction identifiers. Identifier length or format alone is benign, but when the app identity is highly confident, a provider-label/identifier mismatch can be one replica signal if a separate wording, branding, component, or bank-identity inconsistency is also visible. Judge the combination, not a remembered template.

When a payment receipt is forwarded inside WhatsApp, SMS, a gallery, or another viewer, treat the surrounding wrapper as context rather than part of the payment app. Inspect the embedded receipt separately and do not mistake wrapper fonts, status bars, or compression for receipt tampering.

Populate every schema field. Put possible scam context in content_risk_signals, never in tampering_evidence unless it also supports visible screenshot fabrication or editing."""


ANALYST_PROMPT = """Inspect the whole screenshot carefully.

1. Identify the app only when supported by visible branding; otherwise use Unknown.
2. Transcribe the success heading, transaction-ID label/value, and other visible fields exactly; do not silently correct spelling.
3. Separate payment state from screenshot authenticity.
4. Look for localized editing artifacts, impossible internal contradictions, and combinations of replica-app signals. A clean fake-app render may have no paste boundary.
5. List benign limitations so they are not reused as fraud evidence.
6. Estimate fake_probability for screenshot fabrication/editing only.

Use clear_manipulation only when at least one strong, specific item exists in tampering_evidence or an impossible contradiction is directly visible."""


REPLICA_TRIAGE_PROMPT = """Perform a compact, independent fake/clone payment-app triage.

Quote the visible success heading, transaction-ID label, and transaction ID exactly without fixing spelling. Extract the amount, UPI ID, names, bank, and timestamp when visible; otherwise use null. Check four independent signal families: system wording, claimed-app identity/labels, provider-ID coherence, and mixed component/icon/bank styles. A fake-app render can look pixel-clean.

Do not enforce one remembered app template. A single typo, short/alphanumeric ID, missing field, unfamiliar layout, or cross-app UPI handle is never enough. Mark likely_replica only when at least two independent visible signal families conflict and benign app-version, merchant-flow, theme, language, accessibility, crop, or OCR explanations do not resolve the combination.

For example, on a confidently PhonePe-branded screen, an odd system heading, a generic banking-name or transaction label, a provider ID that does not cohere with that label, and generic/mixed bank components form separate signals only when actually visible. Any one of them alone is benign. Keep lists short and specific."""


REPLICA_REVIEW_PROMPT = """Inspect the screenshot independently as a fake/clone payment-app specialist.

Look for combinations of internally inconsistent app identity, system wording, component families, icon geometry, spacing, duplicated elements, and transaction fields. Then try to falsify every suspected signal using app-version, OS, language, theme, merchant-flow, accessibility, crop, and compression explanations. A single typo, missing field, unfamiliar layout, or non-receipt claim is not enough. Inspect an embedded receipt separately from any chat, gallery, or SMS wrapper.

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


def _replica_triage_to_observation(triage: ReplicaTriage) -> PaymentObservation:
    signal_groups = [
        ("wording", triage.wording_errors, "moderate"),
        ("app identity", triage.app_identity_conflicts, "moderate"),
        ("transaction format", triage.transaction_format_anomalies, "weak"),
        ("component style", triage.component_style_conflicts, "moderate"),
    ]
    independent_groups = sum(bool(items) for _, items, _ in signal_groups)
    material_groups = sum(
        bool(items) for _, items, strength in signal_groups if strength != "weak"
    )
    model_confirmed_replica = (
        triage.assessment == "likely_replica"
        and triage.replica_probability >= 65
        and independent_groups >= 2
    )
    high_confidence_multisignal_replica = (
        triage.assessment == "uncertain"
        and triage.app_confidence >= 75
        and triage.replica_probability >= 35
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

    has_signal = bool(evidence)
    assessment = (
        "clear_manipulation"
        if confirmed_replica
        else "uncertain"
        if has_signal or triage.assessment == "uncertain" or triage.replica_probability > 25
        else "no_evidence_of_manipulation"
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
        ),
        tampering_evidence=evidence,
        impossible_inconsistencies=[],
        benign_limitations=triage.benign_explanations,
        content_risk_signals=[],
        authenticity_assessment=assessment,
        fake_probability=max(70, triage.replica_probability)
        if confirmed_replica
        else triage.replica_probability,
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
        )
    value.role = role
    return value


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
            bool(observation.tampering_evidence),
            bool(observation.impossible_inconsistencies),
            observation.readability != "clear",
            observation.confidence != "high",
            observation.screenshot_kind in {"other", "unreadable"},
            observation.app_confidence < 50,
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


def _candidate_signal_suffix(observations: list[PaymentObservation]) -> str:
    candidate_signals = _unique_strings(
        [
            item.description
            for observation in observations
            for item in observation.tampering_evidence
            if item.strength in {"moderate", "strong"}
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


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    analysis_started_at = time.perf_counter()
    prepared_bytes, media_type, dimensions = _prepare_image(image_bytes)
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
            REPLICA_TRIAGE_PROMPT,
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
                f"{REPLICA_TRIAGE_PROMPT}\n\n{REPLICA_REVIEW_PROMPT}",
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
            not observations or any(_needs_review(item) for item in observations)
        )
        if review_required:
            review_views = get_views(REVIEW_MAX_ANALYSIS_VIEWS)
            attempted_passes += 1
            attempted_view_counts["review"] = len(review_views)
            review_prompt = (
                f"{REPLICA_TRIAGE_PROMPT}\n\n{REPLICA_REVIEW_PROMPT}"
                + _candidate_signal_suffix(observations)
            )
            try:
                review_pass = await execute_replica_triage(
                    "review",
                    review_views,
                    review_prompt,
                    REVIEW_MODEL,
                    REVIEW_REASONING_EFFORT,
                    _normalize_image_detail(REVIEW_IMAGE_DETAIL, "auto"),
                    REVIEW_MAX_OUTPUT_TOKENS,
                )
                model_passes.append(review_pass)
                observations.append(review_pass.observation)
            except Exception as exc:
                logger.warning("Payment screenshot replica-review pass failed: %s", exc)
                failures.append(exc)

    adjudicator_performed = False
    if not review_disabled and observations and _needs_adjudication(observations):
        adjudicator_views = get_views(ADJUDICATOR_MAX_ANALYSIS_VIEWS)
        attempted_passes += 1
        attempted_view_counts["adjudicator"] = len(adjudicator_views)
        adjudicator_performed = True
        adjudicator_prompt = ADJUDICATOR_PROMPT + _candidate_signal_suffix(observations)
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
    if len(observations) < 2 and result["verdict"] == "SCAM":
        # A high-risk verdict is never exposed from one model report alone.
        result.update(
            {
                "verdict": "SUSPICIOUS",
                "risk_percentage": 69,
                "confidence": "low",
                "verdict_label": VERDICT_LABELS["SUSPICIOUS"],
                "what_to_do": WHAT_TO_DO["SUSPICIOUS"],
            }
        )
        result["why"].append(
            {
                "en": "Independent forensic consensus was unavailable, so a high-risk verdict was not confirmed.",
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
        }
    )
    return result
