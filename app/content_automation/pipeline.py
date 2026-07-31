from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import httpx
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.content_automation.collectors import collect_all_public_sources
from app.content_automation.config import ContentAutomationConfig
from app.content_automation.integrations import (
    GoogleSearchConsoleClient,
    GoogleSheetsClient,
    GoogleTokenProvider,
    ResearchClient,
    WordPressClient,
)
from app.content_automation.models import ArticleDraft, PipelineSummary, SourceReference, TopicCandidate
from app.content_automation.quality import QualityGate
from app.content_automation.topic_engine import consolidate_candidates, find_related_candidates
from app.content_automation.writer import ArticleWriter
from app.core.database import db

logger = logging.getLogger(__name__)

RUNS = db["content_automation_runs"]
TOPICS = db["content_automation_topics"]


async def ensure_indexes() -> None:
    await RUNS.create_index("locked_until", background=True)
    await TOPICS.create_index([("status", 1), ("updated_at", -1)], background=True)
    await TOPICS.create_index("wordpress_post_id", sparse=True, background=True)


def _run_key(config: ContentAutomationConfig) -> str:
    local_now = datetime.now(timezone.utc).astimezone(config.timezone)
    return f"daily:{local_now.date().isoformat()}"


async def _acquire_run(run_key: str, run_id: str) -> dict | None:
    now = datetime.now(timezone.utc)
    await RUNS.update_one(
        {"_id": run_key},
        {
            "$setOnInsert": {
                "_id": run_key,
                "status": "pending",
                "created_at": now,
                "drafts_created": 0,
            }
        },
        upsert=True,
    )
    existing = await RUNS.find_one({"_id": run_key}, {"status": 1}) or {}
    if existing.get("status") == "completed":
        return None
    return await RUNS.find_one_and_update(
        {
            "_id": run_key,
            "$or": [
                {"locked_until": {"$exists": False}},
                {"locked_until": None},
                {"locked_until": {"$lt": now}},
                {"locked_by": run_id},
            ],
        },
        {
            "$set": {
                "status": "running",
                "locked_by": run_id,
                "locked_until": now + timedelta(hours=4),
                "started_at": now,
                "updated_at": now,
            },
            "$inc": {"attempts": 1},
        },
        return_document=ReturnDocument.AFTER,
    )


async def _finish_run(run_key: str, run_id: str, summary: PipelineSummary, status: str) -> None:
    await RUNS.update_one(
        {"_id": run_key, "locked_by": run_id},
        {
            "$set": {
                "status": status,
                "drafts_created": summary.drafts_created,
                "summary": asdict(summary),
                "finished_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            "$unset": {"locked_by": "", "locked_until": ""},
        },
    )


async def _claim_topic(candidate: TopicCandidate, run_key: str) -> bool:
    now = datetime.now(timezone.utc)
    try:
        await TOPICS.insert_one(
            {
                "_id": candidate.key,
                "topic": candidate.title,
                "primary_keyword": candidate.primary_keyword,
                "secondary_keywords": candidate.secondary_keywords,
                "opportunity_score": candidate.opportunity_score,
                "why_chosen": candidate.why_chosen,
                "run_key": run_key,
                "status": "claimed",
                "attempts": 1,
                "created_at": now,
                "updated_at": now,
            }
        )
        return True
    except DuplicateKeyError:
        existing = await TOPICS.find_one({"_id": candidate.key}, {"status": 1, "attempts": 1}) or {}
        status = existing.get("status")
        if status in {"claimed", "generated"}:
            return True
        if status == "failed" and int(existing.get("attempts", 1)) < 3:
            await TOPICS.update_one(
                {"_id": candidate.key, "status": "failed"},
                {
                    "$set": {"status": "claimed", "run_key": run_key, "updated_at": now},
                    "$inc": {"attempts": 1},
                },
            )
            return True
        return False


async def _set_topic(candidate: TopicCandidate, **values) -> None:
    values["updated_at"] = datetime.now(timezone.utc)
    await TOPICS.update_one({"_id": candidate.key}, {"$set": values})


def _restore_article(value: dict) -> ArticleDraft:
    data = dict(value)
    data["references"] = [
        item if isinstance(item, SourceReference) else SourceReference(**item)
        for item in data.get("references", [])
    ]
    return ArticleDraft(**data)


def _opportunity_rows(candidates: list[TopicCandidate], selected_keys: set[str], run_date: str) -> list[list]:
    rows = []
    for candidate in candidates[:25]:
        rows.append(
            [
                run_date,
                candidate.key,
                candidate.title,
                candidate.why_chosen,
                candidate.opportunity_score,
                candidate.primary_keyword,
                ", ".join(candidate.secondary_keywords),
                " | ".join(reference.url for reference in candidate.source_references),
                "Selected" if candidate.key in selected_keys else "Candidate",
                "",
            ]
        )
    return rows


class ContentAutomationPipeline:
    def __init__(self, config: ContentAutomationConfig):
        self.config = config
        self.tokens = GoogleTokenProvider(config.google_service_account_info)
        self.gsc = GoogleSearchConsoleClient(config, self.tokens)
        self.sheets = GoogleSheetsClient(config, self.tokens)
        self.wordpress = WordPressClient(config)
        self.research = ResearchClient(config)
        self.writer = ArticleWriter(config) if config.openai_api_key else None
        self.quality = QualityGate(config.site_url, config.quality_threshold)

    async def _collect(self) -> tuple[list[TopicCandidate], list[list]]:
        public_task = collect_all_public_sources(self.config)
        gsc_task = self.gsc.collect_candidates()
        performance_task = self.gsc.performance_rows()
        public, gsc, performance = await asyncio.gather(public_task, gsc_task, performance_task)
        return public + gsc, performance

    async def run(self, *, dry_run: bool = False, limit: int | None = None) -> PipelineSummary:
        errors = self.config.validate_for_run(dry_run=dry_run)
        if errors:
            raise RuntimeError("; ".join(errors))
        limit = max(1, min(3, limit or self.config.max_drafts_per_day))
        run_key = _run_key(self.config)
        run_date = run_key.split(":", 1)[1]
        summary = PipelineSummary(run_key=run_key)

        candidates, performance_rows = await self._collect()
        summary.candidates_collected = len(candidates)
        ranked = consolidate_candidates(candidates, self.config)
        summary.candidates_after_dedup = len(ranked)
        eligible = [
            item for item in ranked
            if item.opportunity_score >= self.config.minimum_opportunity_score
        ]

        if dry_run:
            summary.selected = min(limit, len(eligible))
            summary.finished_at = datetime.now(timezone.utc)
            return summary

        await ensure_indexes()
        run_id = uuid.uuid4().hex
        state = await _acquire_run(run_key, run_id)
        if state is None:
            summary.skipped = 1
            summary.finished_at = datetime.now(timezone.utc)
            return summary
        if not state:
            raise RuntimeError(f"Content automation is already running for {run_key}")

        try:
            prior_drafts = int(state.get("drafts_created", 0) or 0)
            summary.drafts_created = prior_drafts
            remaining_slots = max(0, limit - prior_drafts)
            if self.sheets.configured:
                try:
                    await self.sheets.bootstrap()
                    if performance_rows and not state.get("performance_logged"):
                        await self.sheets.append_rows("Performance", performance_rows)
                        await RUNS.update_one(
                            {"_id": run_key, "locked_by": run_id},
                            {"$set": {"performance_logged": True}},
                        )
                except Exception as exc:
                    logger.warning("Google Sheet setup/performance logging failed: %s", exc)

            selected = []
            for candidate in eligible:
                if len(selected) >= remaining_slots:
                    break
                if await _claim_topic(candidate, run_key):
                    selected.append(candidate)
            summary.selected = len(selected)

            if self.sheets.configured and not state.get("opportunities_logged"):
                try:
                    await self.sheets.append_rows(
                        "Topic Opportunities",
                        _opportunity_rows(ranked, {item.key for item in selected}, run_date),
                    )
                    await RUNS.update_one(
                        {"_id": run_key, "locked_by": run_id},
                        {"$set": {"opportunities_logged": True}},
                    )
                except Exception as exc:
                    logger.warning("Topic opportunity logging failed: %s", exc)

            for candidate in selected:
                try:
                    existing = await TOPICS.find_one({"_id": candidate.key}) or {}
                    if existing.get("status") == "completed":
                        summary.skipped += 1
                        continue

                    article = None
                    report = None
                    if existing.get("article") and existing.get("quality", {}).get("passed"):
                        article = _restore_article(existing["article"])
                        report = self.quality.evaluate(article)
                    else:
                        related = find_related_candidates(candidate, ranked)
                        references = await self.research.build_source_pack(candidate, related)
                        if len(references) < self.config.minimum_sources:
                            await _set_topic(
                                candidate,
                                status="skipped_insufficient_sources",
                                source_count=len(references),
                            )
                            summary.skipped += 1
                            continue

                        internal_links = await self.wordpress.internal_links(candidate.primary_keyword)
                        article = await self.writer.write(candidate, references, internal_links)
                        report = self.quality.evaluate(article)
                        await _set_topic(
                            candidate,
                            status="generated" if report.passed else "quality_failed",
                            article=asdict(article),
                            quality=asdict(report),
                        )
                    if not report.passed:
                        summary.skipped += 1
                        continue

                    post = await self.wordpress.create_draft(article)
                    post_id = int(post["id"])
                    draft_url = post.get("link") or post.get("guid", {}).get("rendered", "")
                    await _set_topic(
                        candidate,
                        status="completed",
                        wordpress_post_id=post_id,
                        wordpress_draft_url=draft_url,
                        completed_at=datetime.now(timezone.utc),
                    )
                    summary.drafts_created += 1
                    if draft_url:
                        summary.draft_urls.append(draft_url)

                    if self.sheets.configured:
                        try:
                            await self.sheets.append_rows(
                                "Drafts",
                                [[
                                    run_date,
                                    post_id,
                                    draft_url,
                                    article.title,
                                    article.slug,
                                    report.score,
                                    article.primary_keyword,
                                    ", ".join(article.secondary_keywords),
                                    report.metrics.get("source_count", 0),
                                    report.metrics.get("internal_link_count", 0),
                                    "Pending Review",
                                ]],
                            )
                        except Exception as exc:
                            logger.warning("Draft Sheet logging failed post_id=%s: %s", post_id, exc)
                except Exception as exc:
                    await _set_topic(
                        candidate,
                        status="failed",
                        error=f"{type(exc).__name__}: {str(exc)[:500]}",
                    )
                    summary.failed += 1
                    summary.errors.append(f"{candidate.title}: {type(exc).__name__}: {str(exc)[:200]}")

            summary.finished_at = datetime.now(timezone.utc)
            final_status = "failed" if summary.failed and summary.drafts_created == prior_drafts else "completed"
            await _finish_run(run_key, run_id, summary, final_status)
            return summary
        except BaseException:
            summary.finished_at = datetime.now(timezone.utc)
            await _finish_run(run_key, run_id, summary, "failed")
            raise
