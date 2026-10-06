"""Configure the approved SenseNova endpoint without storing a plaintext key."""

import getpass
import argparse
import json
from pathlib import Path
import sys
import warnings

from datafence.credentials import save_key
from datafence.runtime_lock import RuntimeLock


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / "runtime")
    root = parser.parse_args().data_dir.resolve()
    if not sys.stdin.isatty():
        raise SystemExit("An interactive terminal is required for hidden credential entry.")
    with RuntimeLock(root), warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        save_key(root / "secrets", getpass.getpass("SenseNova API key (hidden): "))
        config = {"provider": "sensenova", "model": "sensenova-6.8-flash-lite",
                  "daily_requests": 100, "daily_tokens": 200000, "max_output_tokens": 2400}
        (root / "llm.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    print("SenseNova configured. Credential encrypted for the current Windows user; restart DataFence.")
