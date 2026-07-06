from __future__ import annotations

import asyncio
import csv
import hashlib
import itertools
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.database import db
from app.services.ai_engine import call_ai_url_full_analysis
from app.services.cache_service import get_cached_result, set_cached_result
from app.services.public_pages_service import normalize_domain, pages_collection
from app.services.security import is_scammer_testing_url
from app.services.url_checker import analyze_url_full
from app.services.website_screenshot import capture_website_screenshot


STATE_COLLECTION = db["domain_seed_state"]
ITEMS_COLLECTION = db["domain_seed_items"]

DEFAULT_LIMIT = 50
HEADER_NAMES = {"domain", "domains", "url", "urls", "website", "websites", "site", "host"}


@dataclass
class SeedSummary:
    seed_id: str
    csv_path: str
    requested_limit: int
    processed: int = 0
    skipped: int = 0
    failed: int = 0
    remaining: int = 0
    rows_read: int = 0
    start_row: int = 0
    last_row: int = 0
    eof: bool = False
    skip_reasons: dict[str, int] = field(default_factory=dict)
    failed_domains: list[str] = field(default_factory=list)
    processed_domains: list[str] = field(default_factory=list)

    def add_skip(self, reason: str) -> None:
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1


@dataclass
class SeedOptions:
    csv_path: Path
    limit: int = DEFAULT_LIMIT
    seed_id: str | None = None
    domain_column: str | None = None
    encoding: str = "utf-8-sig"
    lock_minutes: int = 180
    delay_seconds: float = 0.0


@dataclass
class ScanResult:
    response: dict
    source: str
    verdict: str
    risk_score: int


class PagePublishError(RuntimeError):
    pass


def default_progress(message: str) -> None:
    print(message, flush=True)


def build_seed_id(csv_path: Path, explicit_seed_id: str | None = None) -> str:
    if explicit_seed_id:
        return explicit_seed_id.strip()
    normalized_path = str(csv_path.resolve()).lower()
    digest = hashlib.sha256(normalized_path.encode()).hexdigest()[:16]
    return f"csv:{digest}"


def scan_url_for_domain(domain: str) -> str:
    return f"https://{domain}"


def _item_id(seed_id: str, domain: str) -> str:
    return f"{seed_id}:{domain}"


def _scan_id(seed_id: str, domain: str) -> str:
    return f"domain_seed_scan:{seed_id}:{domain}"


def _clean_header(value: str) -> str:
    return (value or "").strip().lower().replace(" ", "_")


def _choose_column(first_row: list[str], domain_column: str | None) -> tuple[int, bool]:
    cleaned = [_clean_header(cell) for cell in first_row]

    if domain_column:
        wanted = _clean_header(domain_column)
        if wanted not in cleaned:
            raise ValueError(f"CSV column '{domain_column}' was not found.")
        return cleaned.index(wanted), True

    for idx, header in enumerate(cleaned):
        if header in HEADER_NAMES:
            return idx, True

    return 0, False


def iter_csv_candidates(
    csv_path: Path,
    *,
    domain_column: str | None = None,
    encoding: str = "utf-8-sig",
) -> Iterable[tuple[int, str]]:
    with csv_path.open("r", newline="", encoding=encoding) as handle:
        reader = csv.reader(handle)
        first_row = next(reader, None)
        if first_row is None:
            return

        column_index, has_header = _choose_column(first_row, domain_column)
        if has_header:
            rows = enumerate(reader, start=2)
        else:
            rows = enumerate(itertools.chain([first_row], reader), start=1)

        for row_number, row in rows:
            raw_value = row[column_index].strip() if column_index < len(row) else ""
            yield row_number, raw_value


async def ensure_seed_indexes() -> None:
    await ITEMS_COLLECTION.create_index([("seed_id", 1), ("status", 1)], background=True)
    await ITEMS_COLLECTION.create_index([("seed_id", 1), ("first_row_number", 1)], background=True)
    await STATE_COLLECTION.create_index("locked_until", background=True)


async def acquire_seed_lock(options: SeedOptions, seed_id: str, run_id: str) -> dict:
    now = datetime.utcnow()
    csv_path = str(options.csv_path.resolve())
    await STATE_COLLECTION.update_one(
        {"_id": seed_id},
        {
            "$setOnInsert": {
                "_id": seed_id,
                "csv_path": csv_path,
                "last_row_number": 0,
                "created_at": now,
                "completed_runs": 0,
            }
        },
        upsert=True,
    )

    locked_until = now + timedelta(minutes=options.lock_minutes)
    state = await STATE_COLLECTION.find_one_and_update(
        {
            "_id": seed_id,
            "$or": [
                {"locked_until": {"$exists": False}},
                {"locked_until": None},
                {"locked_until": {"$lt": now}},
                {"locked_by": run_id},
            ],
        },
        {
            "$set": {
                "csv_path": csv_path,
                "locked_by": run_id,
                "locked_until": locked_until,
                "updated_at": now,
            }
        },
        return_document=ReturnDocument.AFTER,
    )
    if state:
        return state

    current = await STATE_COLLECTION.find_one({"_id": seed_id}) or {}
    raise RuntimeError(
        "Seeder is already running for this CSV "
        f"(locked_by={current.get('locked_by')}, locked_until={current.get('locked_until')})."
    )


async def refresh_seed_lock(seed_id: str, run_id: str, lock_minutes: int) -> None:
    await STATE_COLLECTION.update_one(
        {"_id": seed_id, "locked_by": run_id},
        {"$set": {"locked_until": datetime.utcnow() + timedelta(minutes=lock_minutes)}},
    )


async def release_seed_lock(seed_id: str, run_id: str) -> None:
    await STATE_COLLECTION.update_one(
        {"_id": seed_id, "locked_by": run_id},
        {
            "$unset": {"locked_by": "", "locked_until": ""},
            "$inc": {"completed_runs": 1},
            "$set": {"updated_at": datetime.utcnow()},
        },
    )


async def update_seed_position(seed_id: str, row_number: int, domain: str | None = None) -> None:
    payload = {
        "last_row_number": row_number,
        "updated_at": datetime.utcnow(),
    }
    if domain:
        payload["last_domain"] = domain
    await STATE_COLLECTION.update_one({"_id": seed_id}, {"$set": payload})


async def public_page_exists(domain: str) -> bool:
    return await pages_collection.find_one({"_id": domain}, {"_id": 1}) is not None


async def mark_existing_page(seed_id: str, run_id: str, domain: str, row_number: int, raw_value: str) -> None:
    now = datetime.utcnow()
    item_id = _item_id(seed_id, domain)
    existing = await ITEMS_COLLECTION.find_one({"_id": item_id}, {"status": 1})
    if existing:
        payload = {
            "last_seen_row_number": row_number,
            "updated_at": now,
            "run_id": run_id,
        }
        if existing.get("status") != "completed":
            payload["status"] = "skipped_existing_page"
        await ITEMS_COLLECTION.update_one({"_id": item_id}, {"$set": payload})
        return

    await ITEMS_COLLECTION.insert_one(
        {
            "_id": _item_id(seed_id, domain),
            "seed_id": seed_id,
            "domain": domain,
            "first_row_number": row_number,
            "last_seen_row_number": row_number,
            "raw_value": raw_value,
            "status": "skipped_existing_page",
            "run_id": run_id,
            "created_at": now,
            "updated_at": now,
        }
    )


async def claim_domain(seed_id: str, run_id: str, domain: str, row_number: int, raw_value: str) -> tuple[bool, str]:
    now = datetime.utcnow()
    doc = {
        "_id": _item_id(seed_id, domain),
        "seed_id": seed_id,
        "domain": domain,
        "first_row_number": row_number,
        "last_seen_row_number": row_number,
        "raw_value": raw_value,
        "status": "processing",
        "run_id": run_id,
        "attempts": 1,
        "created_at": now,
        "updated_at": now,
    }
    try:
        await ITEMS_COLLECTION.insert_one(doc)
        return True, "claimed"
    except DuplicateKeyError:
        existing = await ITEMS_COLLECTION.find_one({"_id": doc["_id"]}) or {}
        status = existing.get("status")
        if status in {"processing", "response_ready"}:
            await ITEMS_COLLECTION.update_one(
                {"_id": doc["_id"]},
                {
                    "$set": {
                        "run_id": run_id,
                        "last_seen_row_number": row_number,
                        "updated_at": now,
                    },
                    "$inc": {"attempts": 1},
                },
            )
            return True, "resumed_processing"
        return False, status or "already_seen"


def scan_result_from_item(item: dict | None) -> ScanResult | None:
    if not item or not item.get("response"):
        return None
    return ScanResult(
        response=item["response"],
        source=item.get("scan_source", "stored_response"),
        verdict=item.get("verdict", "UNKNOWN"),
        risk_score=int(item.get("risk_score", 0) or 0),
    )


async def store_domain_result(seed_id: str, domain: str, result: ScanResult) -> None:
    await ITEMS_COLLECTION.update_one(
        {"_id": _item_id(seed_id, domain)},
        {
            "$set": {
                "status": "response_ready",
                "response": result.response,
                "scan_source": result.source,
                "verdict": result.verdict,
                "risk_score": result.risk_score,
                "updated_at": datetime.utcnow(),
            }
        },
    )


async def save_seed_scan_record(seed_id: str, run_id: str, domain: str, url: str, result: ScanResult) -> None:
    now = datetime.utcnow()
    await db.scam_checks.update_one(
        {"_id": _scan_id(seed_id, domain)},
        {
            "$setOnInsert": {
                "_id": _scan_id(seed_id, domain),
                "type": "url",
                "content": url[:2000],
                "client_ip": "domain-seeder",
                "user_agent": "ScamDekho Domain Seeder",
                "seed_id": seed_id,
                "source": "domain_csv_seeder",
                "created_at": now,
            },
            "$set": {
                "verdict": result.verdict,
                "risk_score": result.risk_score,
                "seed_run_id": run_id,
                "updated_at": now,
            },
        },
        upsert=True,
    )


async def mark_domain_complete(seed_id: str, domain: str, result: ScanResult) -> None:
    await ITEMS_COLLECTION.update_one(
        {"_id": _item_id(seed_id, domain)},
        {
            "$set": {
                "status": "completed",
                "scan_source": result.source,
                "verdict": result.verdict,
                "risk_score": result.risk_score,
                "updated_at": datetime.utcnow(),
            },
            "$unset": {"response": ""},
        },
    )


async def mark_domain_failed(seed_id: str, domain: str, error: Exception) -> None:
    await ITEMS_COLLECTION.update_one(
        {"_id": _item_id(seed_id, domain)},
        {
            "$set": {
                "status": "failed",
                "error": f"{type(error).__name__}: {str(error)[:500]}",
                "updated_at": datetime.utcnow(),
            }
        },
    )


async def run_existing_url_workflow(url: str, *, seed_id: str, run_id: str) -> ScanResult:
    if not url.startswith("http"):
        url = "https://" + url

    if is_scammer_testing_url(url):
        raise ValueError("Invalid URL")

    cached = await get_cached_result(url)
    if cached:
        cached.pop("from_cache", None)
        verdict = cached.get("verdict", "UNKNOWN")
        trust_score = int(cached.get("trust_score", 50))
        return ScanResult(cached, "cache", verdict, max(0, 100 - trust_score))

    intel = await analyze_url_full(url)

    if intel["blacklisted"]:
        screenshot = await capture_website_screenshot(url)
        ai = call_ai_url_full_analysis(screenshot, intel)

        if ai:
            response = {
                "verdict": "SCAM",
                "confidence": ai["confidence"],
                "why": ai["why"],
                "what_to_do": ai["what_to_do"],
                "how_to_avoid": ai["how_to_avoid"],
                "engine": "BLACKLIST + 14-SOURCE + AI",
                "trust_score": intel["trust_score"],
                "verdict_hi": intel["verdict_hi"],
                "sources": intel["sources"],
                "summary": intel["summary"],
                "top_risks": intel["top_risks"],
                "explanation": intel["explanation"],
                "other_info": intel["other_info"],
            }
            risk_score = max(ai["risk_score"], 90)
            return ScanResult(response, "fresh", "SCAM", risk_score)

        response = {
            "verdict": "SCAM",
            "confidence": {
                "en": "This URL is confirmed dangerous by security databases.",
                "hi": "This URL is confirmed dangerous by security databases.",
            },
            "why": [{"en": r, "hi": r} for r in intel.get("top_risks", ["Blacklisted by security databases"])[:3]],
            "what_to_do": [{"en": "Do not visit this website", "hi": "Do not visit this website"}],
            "how_to_avoid": [{"en": "Always verify URLs before clicking", "hi": "Always verify URLs before clicking"}],
            "engine": "BLACKLIST + 14-SOURCE",
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }
        return ScanResult(response, "fresh", "SCAM", 95)

    screenshot = await capture_website_screenshot(url)
    ai = call_ai_url_full_analysis(screenshot, intel)

    if ai:
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        engine = "SCREENSHOT + 14-SOURCE + AI" if screenshot else "14-SOURCE + AI (no screenshot)"
        response = {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": engine,
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }
        return ScanResult(response, "fresh", verdict, ai["risk_score"])

    trust_score = intel["trust_score"]
    verdict = "SCAM" if trust_score < 40 else "SAFE"
    response = {
        "verdict": verdict,
        "confidence": {
            "en": f"Trust score: {trust_score}/100 - {intel['verdict']}",
            "hi": intel["verdict_hi"],
        },
        "why": [{"en": r, "hi": r} for r in intel.get("explanation", [])[:3]],
        "what_to_do": [{"en": "Exercise caution with this website", "hi": "Exercise caution with this website"}],
        "how_to_avoid": [{"en": "Verify website authenticity before sharing data", "hi": "Verify website authenticity before sharing data"}],
        "engine": "14-SOURCE SCORING ENGINE",
        "trust_score": trust_score,
        "verdict_hi": intel["verdict_hi"],
        "sources": intel["sources"],
        "summary": intel["summary"],
        "top_risks": intel["top_risks"],
        "explanation": intel["explanation"],
        "other_info": intel["other_info"],
    }
    risk_score = 100 - trust_score
    return ScanResult(response, "fresh", verdict, risk_score)


async def publish_scan_result(url: str, domain: str, result: ScanResult) -> None:
    await set_cached_result(url, result.response)
    if not await public_page_exists(domain):
        raise PagePublishError("scan result was cached but public page was not created")


async def count_remaining_candidates(options: SeedOptions, seed_id: str, start_after_row: int) -> int:
    remaining = 0
    batch: list[str] = []
    queued: set[str] = set()

    async def flush_batch() -> int:
        if not batch:
            return 0
        ids = [_item_id(seed_id, domain) for domain in batch]
        item_cursor = ITEMS_COLLECTION.find({"_id": {"$in": ids}}, {"domain": 1})
        seen = {doc["domain"] async for doc in item_cursor}
        page_cursor = pages_collection.find({"_id": {"$in": batch}}, {"_id": 1})
        existing_pages = {doc["_id"] async for doc in page_cursor}
        count = sum(1 for domain in batch if domain not in seen and domain not in existing_pages)
        batch.clear()
        return count

    for row_number, raw_value in iter_csv_candidates(
        options.csv_path,
        domain_column=options.domain_column,
        encoding=options.encoding,
    ):
        if row_number <= start_after_row:
            continue
        domain = normalize_domain(raw_value)
        if not domain or domain in queued:
            continue
        queued.add(domain)
        batch.append(domain)
        if len(batch) >= 500:
            remaining += await flush_batch()

    remaining += await flush_batch()
    return remaining


async def seed_domains_from_csv(
    options: SeedOptions,
    *,
    progress: Callable[[str], None] = default_progress,
) -> SeedSummary:
    if options.limit < 1:
        raise ValueError("limit must be at least 1")
    if not options.csv_path.exists():
        raise FileNotFoundError(options.csv_path)

    await ensure_seed_indexes()

    seed_id = build_seed_id(options.csv_path, options.seed_id)
    run_id = uuid.uuid4().hex
    state = await acquire_seed_lock(options, seed_id, run_id)
    last_row_number = int(state.get("last_row_number") or 0)

    summary = SeedSummary(
        seed_id=seed_id,
        csv_path=str(options.csv_path.resolve()),
        requested_limit=options.limit,
        start_row=last_row_number + 1,
        last_row=last_row_number,
    )

    progress(f"Seed ID: {seed_id}")
    progress(f"CSV: {summary.csv_path}")
    progress(f"Starting after row: {last_row_number}")
    progress(f"Run limit: {options.limit}")

    try:
        for row_number, raw_value in iter_csv_candidates(
            options.csv_path,
            domain_column=options.domain_column,
            encoding=options.encoding,
        ):
            if row_number <= last_row_number:
                continue

            summary.rows_read += 1
            summary.last_row = row_number
            domain = normalize_domain(raw_value)

            if not domain:
                summary.add_skip("invalid_domain")
                await update_seed_position(seed_id, row_number)
                await refresh_seed_lock(seed_id, run_id, options.lock_minutes)
                continue

            if await public_page_exists(domain):
                item = await ITEMS_COLLECTION.find_one({"_id": _item_id(seed_id, domain)})
                result = scan_result_from_item(item)
                if result:
                    await save_seed_scan_record(seed_id, run_id, domain, scan_url_for_domain(domain), result)
                    await mark_domain_complete(seed_id, domain, result)
                    summary.processed += 1
                    summary.processed_domains.append(domain)
                    progress(f"[recovered] row={row_number} domain={domain} reason=public_page_exists")
                else:
                    await mark_existing_page(seed_id, run_id, domain, row_number, raw_value)
                    summary.add_skip("existing_public_page")
                    progress(f"[skip] row={row_number} domain={domain} reason=existing_public_page")
                await update_seed_position(seed_id, row_number, domain)
                await refresh_seed_lock(seed_id, run_id, options.lock_minutes)
                if summary.processed + summary.failed >= options.limit:
                    break
                continue

            claimed, claim_status = await claim_domain(seed_id, run_id, domain, row_number, raw_value)
            if not claimed:
                summary.add_skip(claim_status)
                await update_seed_position(seed_id, row_number, domain)
                await refresh_seed_lock(seed_id, run_id, options.lock_minutes)
                progress(f"[skip] row={row_number} domain={domain} reason={claim_status}")
                continue

            slot = summary.processed + summary.failed + 1
            progress(f"[{slot}/{options.limit}] scanning row={row_number} domain={domain}")
            started = time.monotonic()
            result = None
            try:
                url = scan_url_for_domain(domain)
                item = await ITEMS_COLLECTION.find_one({"_id": _item_id(seed_id, domain)})
                result = scan_result_from_item(item)
                if result:
                    progress(f"[resume] domain={domain} using stored scan response")
                else:
                    result = await run_existing_url_workflow(url, seed_id=seed_id, run_id=run_id)
                    await store_domain_result(seed_id, domain, result)

                await save_seed_scan_record(seed_id, run_id, domain, url, result)
                await publish_scan_result(url, domain, result)
                await mark_domain_complete(seed_id, domain, result)
            except PagePublishError as exc:
                progress(
                    f"[retry-later] domain={domain} error={type(exc).__name__}: "
                    f"{str(exc)[:180]} progress_not_advanced"
                )
                raise
            except Exception as exc:
                await mark_domain_failed(seed_id, domain, exc)
                summary.failed += 1
                summary.failed_domains.append(domain)
                progress(f"[failed] domain={domain} error={type(exc).__name__}: {str(exc)[:180]}")
                await update_seed_position(seed_id, row_number, domain)
            else:
                summary.processed += 1
                summary.processed_domains.append(domain)
                elapsed = time.monotonic() - started
                progress(
                    f"[ok] domain={domain} verdict={result.verdict} "
                    f"source={result.source} elapsed={elapsed:.1f}s"
                )
                await update_seed_position(seed_id, row_number, domain)

            await refresh_seed_lock(seed_id, run_id, options.lock_minutes)

            if options.delay_seconds > 0:
                await asyncio.sleep(options.delay_seconds)

            if summary.processed + summary.failed >= options.limit:
                break
        else:
            summary.eof = True

        summary.remaining = await count_remaining_candidates(options, seed_id, summary.last_row)
        return summary
    finally:
        await release_seed_lock(seed_id, run_id)
