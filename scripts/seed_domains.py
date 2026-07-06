from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

load_dotenv(ROOT_DIR / ".env")

from app.core.database import client  # noqa: E402
from app.services.domain_seed_service import DEFAULT_LIMIT, SeedOptions, seed_domains_from_csv  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed ScamDekho public pages from a CSV of domains.",
    )
    parser.add_argument(
        "--csv",
        required=True,
        dest="csv_path",
        help="Path to the CSV file containing domains or URLs.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Maximum new domains to scan in this run. Default: {DEFAULT_LIMIT}.",
    )
    parser.add_argument(
        "--domain-column",
        default=None,
        help="CSV header name containing the domain/URL. Auto-detected when omitted.",
    )
    parser.add_argument(
        "--seed-id",
        default=None,
        help="Optional stable seed ID. Defaults to a hash of the absolute CSV path.",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8-sig",
        help="CSV text encoding. Default: utf-8-sig.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional delay in seconds between domain scans.",
    )
    parser.add_argument(
        "--lock-minutes",
        type=int,
        default=180,
        help="How long to hold the MongoDB run lock. Default: 180.",
    )
    return parser.parse_args()


def print_summary(summary) -> None:
    print("\nFinal summary")
    print("-------------")
    print(f"Seed ID:    {summary.seed_id}")
    print(f"CSV:        {summary.csv_path}")
    print(f"Rows read:  {summary.rows_read}")
    print(f"Last row:   {summary.last_row}")
    print(f"Processed:  {summary.processed}")
    print(f"Skipped:    {summary.skipped}")
    print(f"Failed:     {summary.failed}")
    print(f"Remaining:  {summary.remaining}")
    print(f"EOF:        {summary.eof}")

    if summary.skip_reasons:
        print("\nSkipped by reason")
        for reason, count in sorted(summary.skip_reasons.items()):
            print(f"- {reason}: {count}")

    if summary.failed_domains:
        print("\nFailed domains")
        for domain in summary.failed_domains:
            print(f"- {domain}")


async def async_main() -> int:
    args = parse_args()
    options = SeedOptions(
        csv_path=Path(args.csv_path),
        limit=args.limit,
        seed_id=args.seed_id,
        domain_column=args.domain_column,
        encoding=args.encoding,
        lock_minutes=args.lock_minutes,
        delay_seconds=args.delay,
    )

    try:
        summary = await seed_domains_from_csv(options)
        print_summary(summary)
        return 1 if summary.failed else 0
    finally:
        client.close()


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
