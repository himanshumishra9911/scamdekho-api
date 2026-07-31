from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
load_dotenv(ROOT_DIR / ".env")

from app.content_automation import ContentAutomationConfig  # noqa: E402
from app.content_automation.integrations import GoogleSheetsClient, GoogleTokenProvider  # noqa: E402
from app.content_automation.pipeline import ContentAutomationPipeline  # noqa: E402
from app.core.database import client  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create up to three source-grounded ScamDekho WordPress drafts.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Draft limit for this run (1-3).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and score topics only; do not call AI, Mongo, Sheets, or WordPress.",
    )
    parser.add_argument(
        "--bootstrap-sheet",
        action="store_true",
        help="Create/format the required tabs in GOOGLE_SHEET_ID, then exit.",
    )
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    config = ContentAutomationConfig.from_env()
    try:
        if args.bootstrap_sheet:
            if not config.google_sheet_id:
                raise RuntimeError("GOOGLE_SHEET_ID is required for --bootstrap-sheet")
            sheets = GoogleSheetsClient(config, GoogleTokenProvider(config.google_service_account_info))
            await sheets.bootstrap()
            print(f"Google Sheet ready: https://docs.google.com/spreadsheets/d/{config.google_sheet_id}")
            return 0

        pipeline = ContentAutomationPipeline(config)
        summary = await pipeline.run(dry_run=args.dry_run, limit=args.limit)
        print(json.dumps(asdict(summary), default=str, indent=2))
        return 1 if summary.failed else 0
    finally:
        client.close()


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
