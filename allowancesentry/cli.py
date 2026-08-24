from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analyze import AnalysisError, analyze_snapshot
from .explain import explain_local


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a block-pinned EVM allowance snapshot offline.")
    parser.add_argument("snapshot", help="JSON snapshot file")
    parser.add_argument("--unsigned-out", help="write unsigned revocation calls to this JSON file")
    parser.add_argument("--ai-endpoint", help="optional loopback OpenAI-compatible endpoint")
    parser.add_argument("--ai-model", default="local-model")
    args = parser.parse_args(argv)
    try:
        raw = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        report = analyze_snapshot(raw)
        if args.unsigned_out:
            payload = {
                "snapshot": report["snapshot"],
                "calls": report["unsigned_revocations"],
                "warning": "Unsigned and unsubmitted. Independently verify and simulate before signing.",
            }
            Path(args.unsigned_out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.ai_endpoint:
            report["ai_explanation"] = explain_local(report, args.ai_endpoint, args.ai_model)
            report["ai_disclaimer"] = "AI text is commentary; deterministic fields remain authoritative."
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, AnalysisError) as exc:
        print(f"allowancesentry: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
