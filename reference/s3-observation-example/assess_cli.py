#!/usr/bin/env python3
"""Assess one stored S3 bundle with a receiver policy supplied outside it."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import runpy
import sys

NATIVE = Path(__file__).resolve().with_name('assess_observation.py')


def _policy_inside_bundle(policy: Path, bundle: Path) -> bool:
    policy, bundle = policy.resolve(), bundle.resolve()
    if policy.is_relative_to(bundle):
        return True
    try:
        bundle_stat = bundle.stat()
    except (FileNotFoundError, NotADirectoryError):
        # Leave absent evidence to the fixed evaluator's insufficient result.
        return False
    # resolve() may preserve case and Unicode aliases for the same directory.
    for candidate in (policy, *policy.parents):
        try:
            candidate_stat = candidate.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if os.path.samestat(candidate_stat, bundle_stat):
            return True
    return False


def _run_native(args):
    # Execute the fixed script's source, as a direct CLI invocation does. An
    # import could instead execute a timestamp-valid, stale assessor .pyc.
    previous_argv = sys.argv
    # Bind values to their options so relative names beginning with '-' stay values.
    sys.argv = [str(NATIVE), f'--bundle={args.bundle}', f'--trust={args.trust}']
    try:
        runpy.run_path(str(NATIVE), run_name='__main__')
    except SystemExit as exc:
        return exc.code
    finally:
        sys.argv = previous_argv


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--trust', type=Path, required=True,
                        help='Receiver-selected policy outside the bundle')
    args = parser.parse_args(argv)
    try:
        if _policy_inside_bundle(args.trust, args.bundle):
            raise ValueError('trust policy must be supplied outside the bundle')
    except (OSError, ValueError, RuntimeError) as exc:
        value = {'assessment': 'insufficient',
                 'diagnostics': [{'kind': 'receiver_configuration', 'detail': str(exc)}],
                 'retry_authorized': False}
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 2
    # Preserve the supplied path so native bundle symlink rejection still runs.
    return _run_native(args)


if __name__ == '__main__':
    raise SystemExit(main())
