#!/usr/bin/env python3
"""Replay the included S3 observations offline; no storage service is started."""
import argparse
from pathlib import Path

from assess_observation import assess
from contract import HERE, decode, encode, write

EXPECTED = {
    'supported': 'supported_under_local_assumptions',
    'actual-403': 'insufficient',
    'actual-404': 'insufficient',
    'historical-v1': 'supported_under_local_assumptions',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=HERE / 'inputs/seaweedfs-4.48')
    parser.add_argument('--output', type=Path, help='Optional new JSON file; existing files are never overwritten')
    args = parser.parse_args()
    instance = args.input / 'instance'
    policy = decode((instance / 'receiver-policy.json').read_bytes())
    records = {name: assess(instance / 'bundles' / name, policy) for name in EXPECTED}
    result = {'all_expected': all(records[name]['assessment'] == expected
                                 and records[name]['retry_authorized'] is False
                                 for name, expected in EXPECTED.items()),
              'basis': 'offline replay of stored local captures', 'assessments': records}
    if args.output:
        write(args.output, result)
    print(encode({'all_expected': result['all_expected'],
                  'assessments': {name: r['assessment'] for name, r in records.items()}}).decode())
    return 0 if result['all_expected'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
