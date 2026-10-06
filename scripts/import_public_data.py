"""Explicit isolated import of the fixed official UCI archive (no cloud model)."""

import argparse
import json
from pathlib import Path

from datafence.public_data import import_bank_marketing, list_datasets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("runtime/public-data"))
    parser.add_argument("--archive", type=Path, help="Optional offline copy; must match the pinned official SHA-256")
    parser.add_argument("--list", action="store_true", help="Read only; never downloads")
    args = parser.parse_args()
    result = list_datasets(args.directory) if args.list else import_bank_marketing(args.directory, args.archive)
    print(json.dumps(result, ensure_ascii=True, indent=2))
