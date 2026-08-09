"""Zero-token forensic checks for known fake-payment screenshot families.

This layer deliberately makes only narrow, auditable claims. Exact hashes catch
previously confirmed samples. Joint perceptual hashes catch small resizes,
re-encodes and text changes inside a confirmed generator template. Unknown
screens continue to the vision cascade instead of being classified by visual
similarity alone.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageOps


SIGNATURE_PATH = Path(__file__).resolve().parents[1] / "data" / "payment_fake_signatures.json"


@dataclass(frozen=True)
class KnownFakeMatch:
    signature_id: str
    family: str
    app_name: str
    app_key: str
    method: str
    phash_distance: int
    dhash_distance: int


@dataclass(frozen=True)
class LocalForensicsResult:
    known_fake: KnownFakeMatch | None
    red_overlay_candidate: bool
    red_overlay_area_ratio: float
    attention_overlay_candidate: bool
    attention_overlay_area_ratio: float
    explicit_overlay_term: str | None
    annotation_overlay_term: str | None
    latency_ms: int

    @property
    def force_review(self) -> bool:
        return (
            self.red_overlay_candidate
            and self.known_fake is None
            and self.annotation_overlay_term is None
        )

    @property
    def needs_overlay_floor(self) -> bool:
        return self.known_fake is None and (
            self.red_overlay_candidate or self.annotation_overlay_term is not None
        )

    def prompt_suffix(self) -> str:
        # OCR is an optional corroborator, not a production dependency.  Render
        # images and low-resolution forwards can make Tesseract miss text that a
        # vision pass can still read.  Supplying the pixel candidate lets the
        # model inspect it; deterministic post-processing still requires the
        # model to localize an explicit warning/fabrication term before applying
        # a verdict floor.
        if not (
            self.red_overlay_candidate
            or self.attention_overlay_candidate
            or self.annotation_overlay_term is not None
        ):
            return ""
        annotation = (
            f' OCR read the warning term "{self.annotation_overlay_term}".'
            if self.annotation_overlay_term
            else ""
        )
        return (
            "\n\nLocal pixel triage found saturated red/magenta annotation ink over the "
            "upper/central payment area. Treat this only as a candidate and inspect "
            "the pixels directly. Transcribe any visible words such as FAKE, scam, "
            "fraud, savdhan, generator, prank, demo, or test. A warning annotation "
            "that overlaps receipt controls proves that the presented image was "
            "annotated, but does not by itself prove the underlying transaction was "
            "fake. Ordinary app branding or an advertisement is not an annotation."
            + annotation
        )

    def telemetry(self) -> dict[str, Any]:
        match = self.known_fake
        return {
            "decision": "known_fake" if match else "model_required",
            "known_fake_match": bool(match),
            "signature_id": match.signature_id if match else None,
            "family": match.family if match else None,
            "method": match.method if match else None,
            "phash_distance": match.phash_distance if match else None,
            "dhash_distance": match.dhash_distance if match else None,
            "red_overlay_candidate": self.red_overlay_candidate,
            "red_overlay_area_ratio": self.red_overlay_area_ratio,
            "attention_overlay_candidate": self.attention_overlay_candidate,
            "attention_overlay_area_ratio": self.attention_overlay_area_ratio,
            "explicit_overlay_term": self.explicit_overlay_term,
            "annotation_overlay_term": self.annotation_overlay_term,
            "latency_ms": self.latency_ms,
        }


@lru_cache(maxsize=1)
def load_known_fake_signatures() -> tuple[dict[str, Any], ...]:
    with SIGNATURE_PATH.open("r", encoding="utf-8") as handle:
        records = json.load(handle)
    if not isinstance(records, list):
        raise ValueError("Payment fake signature registry must contain a JSON list")
    return tuple(records)


def hamming_distance(left: str, right: str) -> int:
    return (int(left, 16) ^ int(right, 16)).bit_count()


def _decode_rgb(image_bytes: bytes) -> np.ndarray:
    with Image.open(io.BytesIO(image_bytes)) as image:
        image.load()
        rgb = ImageOps.exif_transpose(image).convert("RGB")
        return np.asarray(rgb)


def _perceptual_hashes(rgb: np.ndarray) -> tuple[str, str]:
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)

    resized = cv2.resize(gray, (32, 32), interpolation=cv2.INTER_AREA).astype(np.float32)
    low_frequency = cv2.dct(resized)[:8, :8]
    median = np.median(low_frequency[1:, :])
    phash_bits = (low_frequency > median).flatten()
    phash = f"{sum(int(bit) << (63 - index) for index, bit in enumerate(phash_bits)):016x}"

    small = cv2.resize(gray, (9, 8), interpolation=cv2.INTER_AREA)
    dhash_bits = (small[:, 1:] > small[:, :-1]).flatten()
    dhash = f"{sum(int(bit) << (63 - index) for index, bit in enumerate(dhash_bits)):016x}"
    return phash, dhash


def _large_red_overlay(rgb: np.ndarray) -> tuple[bool, float]:
    """Find unusually large red ink over the area where a receipt normally sits.

    The signal only requests model review. It never creates a fake verdict by
    itself, which protects legitimate red app logos and promotional cards.
    """
    height, width = rgb.shape[:2]
    upper = cv2.cvtColor(rgb[: round(height * 0.70)], cv2.COLOR_RGB2HSV)
    red_mask = cv2.inRange(upper, (0, 130, 80), (12, 255, 255)) | cv2.inRange(
        upper, (168, 130, 80), (180, 255, 255)
    )
    kernel = cv2.getStructuringElement(
        cv2.MORPH_RECT,
        (max(5, width // 40), max(3, height // 150)),
    )
    joined = cv2.morphologyEx(red_mask, cv2.MORPH_CLOSE, kernel)
    component_count, _, stats, _ = cv2.connectedComponentsWithStats(joined)
    if component_count <= 1:
        return False, 0.0

    component = stats[1 + int(np.argmax(stats[1:, cv2.CC_STAT_AREA]))]
    x, y, component_width, component_height, area = (int(value) for value in component)
    area_ratio = area / float(width * height)
    is_candidate = all(
        (
            float(red_mask.mean() / 255.0) >= 0.015,
            area_ratio >= 0.012,
            component_width >= width * 0.22,
            component_height >= height * 0.03,
            x + component_width > width * 0.20,
            y < height * 0.58,
        )
    )
    return is_candidate, round(area_ratio, 4)


def _large_attention_overlay(rgb: np.ndarray) -> tuple[bool, float]:
    """Find large red-to-magenta annotation ink anywhere over receipt controls.

    This deliberately includes pink/magenta warning captions while excluding
    ordinary low-saturation text. The color candidate alone never changes a
    verdict; a warning word must also be read by OCR.
    """
    height, width = rgb.shape[:2]
    region = cv2.cvtColor(rgb[: round(height * 0.90)], cv2.COLOR_RGB2HSV)
    attention_mask = cv2.inRange(region, (0, 100, 70), (15, 255, 255)) | cv2.inRange(
        region, (135, 70, 70), (180, 255, 255)
    )
    kernel = cv2.getStructuringElement(
        cv2.MORPH_RECT,
        (max(5, width // 40), max(3, height // 150)),
    )
    joined = cv2.morphologyEx(attention_mask, cv2.MORPH_CLOSE, kernel)
    component_count, _, stats, _ = cv2.connectedComponentsWithStats(joined)
    if component_count <= 1:
        return False, 0.0

    component = stats[1 + int(np.argmax(stats[1:, cv2.CC_STAT_AREA]))]
    x, y, component_width, component_height, area = (int(value) for value in component)
    area_ratio = area / float(width * height)
    is_candidate = all(
        (
            float(attention_mask.mean() / 255.0) >= 0.010,
            area_ratio >= 0.008,
            component_width >= width * 0.22,
            component_height >= height * 0.03,
            x + component_width > width * 0.20,
            y < height * 0.86,
        )
    )
    return is_candidate, round(area_ratio, 4)


_EXPLICIT_OVERLAY_TERMS = re.compile(
    r"\b(fake|generator|prank|demo|scam|fraud|savdhan|sawdhan|beware)\b|\btest\s+payment\b",
    re.IGNORECASE,
)

_FABRICATION_OVERLAY_TERMS = {"fake", "generator", "prank", "demo", "test payment"}


def _explicit_overlay_term(text: str) -> str | None:
    match = _EXPLICIT_OVERLAY_TERMS.search(" ".join(str(text).split()))
    return " ".join(match.group(0).casefold().split()) if match else None


def _ocr_attention_overlay(rgb: np.ndarray) -> str | None:
    """Read explicit fabrication or warning labels in red/magenta ink."""
    height, _ = rgb.shape[:2]
    upper_rgb = rgb[: round(height * 0.90)]
    try:
        whole_text = pytesseract.image_to_string(
            Image.fromarray(upper_rgb),
            config="--psm 11",
        )
        if term := _explicit_overlay_term(whole_text):
            return term

        hsv = cv2.cvtColor(upper_rgb, cv2.COLOR_RGB2HSV)
        red_mask = cv2.inRange(hsv, (0, 100, 70), (15, 255, 255)) | cv2.inRange(
            hsv, (135, 70, 70), (180, 255, 255)
        )
        y_values, x_values = np.where(red_mask > 0)
        if not len(x_values):
            return None
        crop = red_mask[
            y_values.min() : y_values.max() + 1,
            x_values.min() : x_values.max() + 1,
        ]
        masked = Image.fromarray(255 - crop)
        for angle in (0, 20, 25, -20, -25):
            rotated = masked.rotate(angle, expand=True, fillcolor=255)
            scale = min(4.0, max(1.0, 900 / max(rotated.width, 1)))
            resized = rotated.resize(
                (round(rotated.width * scale), round(rotated.height * scale))
            )
            text = pytesseract.image_to_string(resized, config="--psm 11")
            if term := _explicit_overlay_term(text):
                return term
    except (pytesseract.TesseractError, OSError, RuntimeError):
        # The Docker image includes Tesseract, but a missing local binary must
        # never break the paid vision fallback.
        return None
    return None


# Backwards-compatible private alias used by older tests/imports.
_ocr_red_overlay = _ocr_attention_overlay


def analyze_local_forensics(image_bytes: bytes) -> LocalForensicsResult:
    started_at = time.perf_counter()
    rgb = _decode_rgb(image_bytes)
    height, width = rgb.shape[:2]
    sha256 = hashlib.sha256(image_bytes).hexdigest()
    phash, dhash = _perceptual_hashes(rgb)
    signatures = load_known_fake_signatures()

    known_fake: KnownFakeMatch | None = None
    for signature in signatures:
        if sha256 != signature["sha256"]:
            continue
        known_fake = KnownFakeMatch(
            signature_id=signature["id"],
            family=signature["family"],
            app_name=signature["app_name"],
            app_key=signature["app_key"],
            method="exact_sha256",
            phash_distance=0,
            dhash_distance=0,
        )
        break

    if known_fake is None:
        aspect_ratio = width / float(height)
        candidates: list[tuple[int, int, dict[str, Any]]] = []
        for signature in signatures:
            if not signature.get("perceptual", False):
                continue
            reference_ratio = signature["width"] / float(signature["height"])
            aspect_delta = abs(aspect_ratio - reference_ratio) / reference_ratio
            if aspect_delta > float(signature.get("aspect_tolerance", 0.06)):
                continue
            phash_distance = hamming_distance(phash, signature["phash"])
            dhash_distance = hamming_distance(dhash, signature["dhash"])
            if (
                phash_distance <= int(signature["phash_threshold"])
                and dhash_distance <= int(signature["dhash_threshold"])
            ):
                candidates.append((phash_distance, dhash_distance, signature))

        if candidates:
            phash_distance, dhash_distance, signature = min(
                candidates, key=lambda item: (item[0] + item[1], item[0], item[1])
            )
            known_fake = KnownFakeMatch(
                signature_id=signature["id"],
                family=signature["family"],
                app_name=signature["app_name"],
                app_key=signature["app_key"],
                method="joint_perceptual_hash",
                phash_distance=phash_distance,
                dhash_distance=dhash_distance,
            )

    red_overlay_candidate, red_area = _large_red_overlay(rgb)
    attention_overlay_candidate, attention_area = _large_attention_overlay(rgb)
    explicit_term = None
    annotation_term = None
    if known_fake is None and (red_overlay_candidate or attention_overlay_candidate):
        explicit_term = _ocr_attention_overlay(rgb)
        if explicit_term in _FABRICATION_OVERLAY_TERMS:
            known_fake = KnownFakeMatch(
                signature_id="explicit-overlay-text",
                family="explicit-fake-overlay",
                app_name="Unknown",
                app_key="unknown",
                method="local_explicit_overlay_ocr",
                phash_distance=-1,
                dhash_distance=-1,
            )
        elif explicit_term:
            annotation_term = explicit_term
    latency_ms = round((time.perf_counter() - started_at) * 1000)
    return LocalForensicsResult(
        known_fake=known_fake,
        red_overlay_candidate=red_overlay_candidate,
        red_overlay_area_ratio=red_area,
        attention_overlay_candidate=attention_overlay_candidate,
        attention_overlay_area_ratio=attention_area,
        explicit_overlay_term=explicit_term,
        annotation_overlay_term=annotation_term,
        latency_ms=latency_ms,
    )
