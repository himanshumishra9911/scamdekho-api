"""Re-evaluate every stored /check/ page against the current quality gate.

Between 2026-08-29 and the commit that added this script, indexability was
decided solely by the major-domain veto: every scanned domain went into the
index and into the sitemap. That put ~7,900 pages — including ones published
with "Domain Created: Unknown" — in front of the September 2026 core update.

This script replays calculate_page_quality() over the stored scan results, so
nothing is rescanned and no paid API is called. Pages that no longer qualify
are flagged noindex and drop out of the sitemap; pages with proven organic
demand (app/data/search_demand_domains.txt) are kept regardless.

Dry run by default — it prints what would change and writes nothing:

    python scripts/reprune_public_pages.py
    python scripts/reprune_public_pages.py --apply
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv
from pymongo import UpdateOne
from pymongo.errors import PyMongoError


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

load_dotenv(ROOT_DIR / ".env")

from app.core.database import client  # noqa: E402
from app.services.public_pages_service import (  # noqa: E402
    calculate_page_quality,
    has_search_demand,
    load_search_demand_domains,
    pages_collection,
    should_index_public_domain,
)

BATCH_SIZE = 500


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Re-evaluate stored /check/ pages against the current quality gate.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the changes. Without this flag the script only reports.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only examine the first N documents. 0 (default) means all of them.",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=15,
        help="How many example domains to print per bucket. Default: 15.",
    )
    return parser.parse_args()


def decide(doc: dict) -> tuple[bool, list[str]]:
    """Return (indexable, reasons) for a stored page document."""
    domain = doc.get("domain") or doc.get("_id") or ""
    result = doc.get("result") or {}

    if not should_index_public_domain(domain):
        return False, ["domain_vetoed"]
    if has_search_demand(domain):
        return True, ["search_demand"]

    quality = calculate_page_quality(result)
    return quality["indexable"], quality["reasons"]


async def main() -> int:
    args = parse_args()

    if not os.getenv("MONGO_URL"):
        print("MONGO_URL is not set.")
        print("Put it in a .env file at the repo root (it is gitignored):")
        print("")
        print("    MONGO_URL=<the value from Render > scamdekho-api > Environment>")
        print("    OPENAI_API_KEY=<any non-empty value; this script makes no API calls>")
        return 2

    demand = load_search_demand_domains()
    if not demand:
        print("WARNING: search-demand list is empty — pages that earn clicks")
        print("         will be judged on scan data alone. Check that")
        print("         app/data/search_demand_domains.txt is present.\n")

    total = 0
    indexed_after = 0
    now_noindex: list[str] = []
    now_indexable: list[str] = []
    unchanged = 0
    reason_counts: Counter[str] = Counter()
    kept_by_demand = 0
    pending: list[tuple[str, bool]] = []
    applied = 0

    async def flush() -> int:
        if not args.apply or not pending:
            pending.clear()
            return 0
        ops = [
            UpdateOne({"_id": doc_id}, {"$set": {"indexable": value}})
            for doc_id, value in pending
        ]
        res = await pages_collection.bulk_write(ops, ordered=False)
        pending.clear()
        return int(getattr(res, "modified_count", 0))

    projection = {"domain": 1, "indexable": 1, "result": 1}
    cursor = pages_collection.find({}, projection)
    if args.limit:
        cursor = cursor.limit(args.limit)

    try:
        async for doc in cursor:
            total += 1
            domain = doc.get("domain") or doc.get("_id") or ""
            was = bool(doc.get("indexable"))
            now, reasons = decide(doc)
            if now:
                indexed_after += 1

            if reasons == ["search_demand"]:
                kept_by_demand += 1
            elif not now:
                for reason in reasons:
                    reason_counts[reason] += 1

            if now == was:
                unchanged += 1
                continue

            (now_indexable if now else now_noindex).append(domain)
            pending.append((doc.get("_id") or domain, now))
            if len(pending) >= BATCH_SIZE:
                applied += await flush()

        applied += await flush()
    except PyMongoError as exc:
        print(f"Could not reach MongoDB: {type(exc).__name__}")
        print(f"  {exc}"[:400])
        print("")
        print("Check that MONGO_URL is correct and that this machine's IP is")
        print("allowed in Atlas (Network Access). Nothing was written.")
        return 1

    print("=" * 62)
    print(f"{'DRY RUN — nothing written' if not args.apply else 'APPLIED'}")
    print("=" * 62)
    print(f"documents examined      : {total:>6}")
    print(f"unchanged               : {unchanged:>6}")
    print(f"flip -> noindex         : {len(now_noindex):>6}")
    print(f"flip -> indexable       : {len(now_indexable):>6}")
    print(f"kept by proven demand   : {kept_by_demand:>6}")
    share = f"{100 * indexed_after / total:.1f}%" if total else "n/a"
    print(f"indexed after this run  : {indexed_after:>6}  ({share} of corpus)")
    if args.apply:
        print(f"documents written       : {applied:>6}")

    if reason_counts:
        print("\nwhy pages fail the gate (one page can fail several):")
        for reason, count in reason_counts.most_common():
            print(f"  {reason:<26} {count:>6}")

    if now_noindex:
        print(f"\nexamples losing index status ({min(args.show, len(now_noindex))} of {len(now_noindex)}):")
        for domain in now_noindex[: args.show]:
            print(f"  {domain}")

    if now_indexable:
        print(f"\nexamples gaining index status ({min(args.show, len(now_indexable))} of {len(now_indexable)}):")
        for domain in now_indexable[: args.show]:
            print(f"  {domain}")

    if not args.apply:
        print("\nRe-run with --apply to write these changes.")
    else:
        print("\nNext: resubmit sitemap-checks.xml in Search Console so the")
        print("removed URLs are recrawled and dropped.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    finally:
        client.close()
