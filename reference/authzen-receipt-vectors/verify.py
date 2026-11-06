#!/usr/bin/env python3
"""Replay saved local histories without running provider operations."""
import argparse
import json
from pathlib import Path
import sys

from vector_contract import ROOT, SAMPLE, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, default=ROOT)
    parser.add_argument("--sample", type=Path, default=SAMPLE)
    args = parser.parse_args()
    try:
        result = verify(args.vectors, args.sample)
    except (ValueError, OSError, KeyError, TypeError, ImportError) as error:
        print(json.dumps({"status": "error", "reason": str(error), "is_execution_ticket": False}))
        return 2
    except RuntimeError as error:
        crypto = sys.modules.get("handoff_constrained_crypto")
        if crypto is None or not isinstance(error, crypto.VerificationUnavailable):
            raise
        print(json.dumps({"status": "unavailable", "reason": error.code, "is_execution_ticket": False}))
        return 3
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
