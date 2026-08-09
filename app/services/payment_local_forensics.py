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
    explicit_overlay_term: str | None
    latency_ms: int

    @property
    def force_review(self) -> bool:
        return self.red_overlay_candidate and self.known_fake is None

    def prompt_suffix(self) -> str:
        if not self.red_overlay_candidate or self.known_fake is not None:
            return ""
        return (
            "\n\nLocal pixel triage found a large, saturated-red graphic over the "
            "upper/central payment area. Treat this only as a candidate and inspect "
            "the pixels directly. Transcribe any visible words such as FAKE, "
            "generator, prank, demo, or test. An explicit fake/generator label or a "
            "material overlay on the receipt is manipulation of the presented "
            "payment proof; ordinary app branding or an advertisement is not."
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
            "explicit_overlay_term": self.explicit_overlay_term,
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


_EXPLICIT_OVERLAY_TERMS = re.compile(
    r"\b(fake|generator|prank)\b",
    re.IGNORECASE,
)


def _explicit_overlay_term(text: str) -> str | None:
    match = _EXPLICIT_OVERLAY_TERMS.search(" ".join(str(text).split()))
    return match.group(1).casefold() if match else None


def _ocr_red_overlay(rgb: np.ndarray) -> str | None:
    """Read explicit fake/generator labels, including a rotated red stamp."""
    height, _ = rgb.shape[:2]
    upper_rgb = rgb[: round(height * 0.70)]
    try:
        whole_text = pytesseract.image_to_string(
            Image.fromarray(upper_rgb),
            config="--psm 11",
        )
        if term := _explicit_overlay_term(whole_text):
            return term

        hsv = cv2.cvtColor(upper_rgb, cv2.COLOR_RGB2HSV)
        red_mask = cv2.inRange(hsv, (0, 100, 80), (14, 255, 255)) | cv2.inRange(
            hsv, (165, 100, 80), (180, 255, 255)
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
    explicit_term = None
    if known_fake is None and red_overlay_candidate:
        explicit_term = _ocr_red_overlay(rgb)
        if explicit_term:
            known_fake = KnownFakeMatch(
                signature_id="explicit-overlay-text",
                family="explicit-fake-overlay",
                app_name="Unknown",
                app_key="unknown",
                method="local_explicit_overlay_ocr",
                phash_distance=-1,
                dhash_distance=-1,
            )
    latency_ms = round((time.perf_counter() - started_at) * 1000)
    return LocalForensicsResult(
        known_fake=known_fake,
        red_overlay_candidate=red_overlay_candidate,
        red_overlay_area_ratio=red_area,
        explicit_overlay_term=explicit_term,
        latency_ms=latency_ms,
    )
