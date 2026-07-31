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


async def _acquire_run(run_key: str, run_id: str, target_drafts: int) -> dict | None:
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
    existing = await RUNS.find_one(
        {"_id": run_key},
        {"status": 1, "drafts_created": 1},
    ) or {}
    if (
        existing.get("status") == "completed"
        and int(existing.get("drafts_created", 0) or 0) >= target_drafts
    ):
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
                "gsc_drafts_created": summary.gsc_drafts_created,
                "news_drafts_created": summary.news_drafts_created,
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
                "source_type": candidate.source_type,
                "selection_bucket": _selection_bucket(candidate),
                "run_key": run_key,
                "status": "claimed",
                "attempts": 1,
                "created_at": now,
                "updated_at": now,
            }
        )
        return True
    except DuplicateKeyError:
        existing = await TOPICS.find_one(
            {"_id": candidate.key},
            {"status": 1, "attempts": 1, "run_key": 1},
        ) or {}
        status = existing.get("status")
        if status in {"claimed", "generated"}:
            return True
        retryable_statuses = {"failed", "skipped_insufficient_sources", "quality_failed"}
        retryable_now = _can_retry_topic(existing, run_key)
        if status in retryable_statuses and retryable_now and int(existing.get("attempts", 1)) < 3:
            await TOPICS.update_one(
                {"_id": candidate.key, "status": status},
                {
                    "$set": {
                        "status": "claimed",
                        "run_key": run_key,
                        "source_type": candidate.source_type,
                        "selection_bucket": _selection_bucket(candidate),
                        "updated_at": now,
                    },
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


def _selection_bucket(candidate: TopicCandidate) -> str:
    return "gsc" if candidate.source_type == "gsc" else "news"


def _can_retry_topic(existing: dict, run_key: str) -> bool:
    status = existing.get("status")
    if status in {"failed", "skipped_insufficient_sources"}:
        return True
    return status == "quality_failed" and existing.get("run_key") != run_key


def _target_quotas(limit: int) -> dict[str, int]:
    news = 1 if limit else 0
    return {"gsc": max(0, limit - news), "news": news}


def _is_blog_worthy(candidate: TopicCandidate) -> bool:
    if candidate.source_type != "gsc":
        return candidate.source_type in {"news", "rss"}
    normalized = " ".join(candidate.title.lower().replace(".", " ").split())
    navigational = {"scamdekho", "scam dekho", "scamdekho in", "scam dekho in"}
    return normalized not in navigational and len(normalized.split()) >= 2


def _gsc_recovery_sort_key(candidate: TopicCandidate) -> tuple[float, ...]:
    lost_clicks = max(0.0, -candidate.click_change)
    lost_impressions = max(0.0, -candidate.impression_change)
    has_decline = 1.0 if lost_clicks or lost_impressions else 0.0
    return (
        has_decline,
        lost_clicks,
        lost_impressions,
        candidate.opportunity_score,
        candidate.impressions,
    )


def build_candidate_pools(candidates: list[TopicCandidate]) -> dict[str, list[TopicCandidate]]:
    pools = {"gsc": [], "news": []}
    for candidate in candidates:
        if not _is_blog_worthy(candidate):
            continue
        pools[_selection_bucket(candidate)].append(candidate)
    pools["gsc"].sort(key=_gsc_recovery_sort_key, reverse=True)
    pools["news"].sort(key=lambda item: item.opportunity_score, reverse=True)
    return pools


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

    async def _collect(
        self,
    ) -> tuple[list[TopicCandidate], list[TopicCandidate], list[list]]:
        public_task = collect_all_public_sources(self.config)
        gsc_task = self.gsc.collect_candidates()
        performance_task = self.gsc.performance_rows()
        public, gsc, performance = await asyncio.gather(public_task, gsc_task, performance_task)
        return public, gsc, performance

    async def run(self, *, dry_run: bool = False, limit: int | None = None) -> PipelineSummary:
        errors = self.config.validate_for_run(dry_run=dry_run)
        if errors:
            raise RuntimeError("; ".join(errors))
        limit = max(1, min(3, limit or self.config.max_drafts_per_day))
        run_key = _run_key(self.config)
        run_date = run_key.split(":", 1)[1]
        summary = PipelineSummary(run_key=run_key)

        public_candidates, gsc_candidates, performance_rows = await self._collect()
        candidates = public_candidates + gsc_candidates
        summary.candidates_collected = len(candidates)
        summary.public_candidates_collected = len(public_candidates)
        summary.gsc_candidates_collected = len(gsc_candidates)
        summary.performance_rows_collected = len(performance_rows)
        ranked = consolidate_candidates(candidates, self.config)
        summary.candidates_after_dedup = len(ranked)
        eligible = [
            item for item in ranked
            if item.opportunity_score >= self.config.minimum_opportunity_score
        ]
        summary.eligible_candidates = len(eligible)
        summary.top_opportunity_score = ranked[0].opportunity_score if ranked else 0.0
        logger.info(
            "Content candidates public=%s gsc=%s ranked=%s eligible=%s top_score=%s threshold=%s",
            summary.public_candidates_collected,
            summary.gsc_candidates_collected,
            summary.candidates_after_dedup,
            summary.eligible_candidates,
            summary.top_opportunity_score,
            self.config.minimum_opportunity_score,
        )

        if dry_run:
            quotas = _target_quotas(limit)
            pools = build_candidate_pools(eligible)
            summary.selected = sum(min(quotas[bucket], len(pools[bucket])) for bucket in quotas)
            summary.finished_at = datetime.now(timezone.utc)
            return summary

        await ensure_indexes()
        run_id = uuid.uuid4().hex
        state = await _acquire_run(run_key, run_id, limit)
        if state is None:
            summary.skipped = 1
            summary.finished_at = datetime.now(timezone.utc)
            return summary
        if not state:
            raise RuntimeError(f"Content automation is already running for {run_key}")

        try:
            prior_drafts = int(state.get("drafts_created", 0) or 0)
            summary.drafts_created = prior_drafts
            summary.gsc_drafts_created = int(state.get("gsc_drafts_created", 0) or 0)
            summary.news_drafts_created = int(state.get("news_drafts_created", 0) or 0)
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

            quotas = _target_quotas(limit)
            pools = build_candidate_pools(eligible)
            attempted_keys = set()
            for bucket in ("gsc", "news"):
                current_count = (
                    summary.gsc_drafts_created if bucket == "gsc"
                    else summary.news_drafts_created
                )
                required = max(0, quotas[bucket] - current_count)
                for candidate in pools[bucket]:
                    if required <= 0 or summary.drafts_created >= limit:
                        break
                    if not await _claim_topic(candidate, run_key):
                        continue
                    attempted_keys.add(candidate.key)
                    summary.selected += 1
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
                                summary.source_skips += 1
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
                            summary.quality_skips += 1
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
                        if bucket == "gsc":
                            summary.gsc_drafts_created += 1
                        else:
                            summary.news_drafts_created += 1
                        required -= 1
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

            if self.sheets.configured and not state.get("opportunities_logged"):
                try:
                    await self.sheets.append_rows(
                        "Topic Opportunities",
                        _opportunity_rows(ranked, attempted_keys, run_date),
                    )
                    await RUNS.update_one(
                        {"_id": run_key, "locked_by": run_id},
                        {"$set": {"opportunities_logged": True}},
                    )
                except Exception as exc:
                    logger.warning("Topic opportunity logging failed: %s", exc)

            summary.finished_at = datetime.now(timezone.utc)
            quotas_met = (
                summary.gsc_drafts_created >= quotas["gsc"]
                and summary.news_drafts_created >= quotas["news"]
                and summary.drafts_created >= limit
            )
            final_status = "completed" if quotas_met else "incomplete"
            await _finish_run(run_key, run_id, summary, final_status)
            return summary
        except BaseException:
            summary.finished_at = datetime.now(timezone.utc)
            await _finish_run(run_key, run_id, summary, "failed")
            raise

