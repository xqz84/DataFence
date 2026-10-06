"""Run an independent offline evaluation and retain all reproducible artifacts."""
import argparse
import json
from pathlib import Path
from datafence.evaluation import run_evaluation

parser = argparse.ArgumentParser()
parser.add_argument("--seed", type=int, default=20260919)
parser.add_argument("--sessions", type=int, default=160)
parser.add_argument("--output", type=Path, default=Path("runtime/evaluations/cli"))
args = parser.parse_args()
if not 24 <= args.sessions <= 1000:
    parser.error("sessions must be in 24..1000")
if args.output.exists() and any(args.output.iterdir()):
    parser.error("output directory is not empty; use a new directory to preserve prior evidence")
report = run_evaluation(args.seed, args.sessions, args.output)
print(json.dumps({"id": report["id"], "metrics": report["metrics"], "output": str(args.output)}, ensure_ascii=False, indent=2))
