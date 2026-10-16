#!/usr/bin/env python3
"""Replay the included S3 observations offline; no storage service is started."""
import argparse
import sys
from pathlib import Path

from assess_observation import assess
from contract import HERE, ROOT, decode, encode, write
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from historical import historical_api

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
    parser.add_argument('--runtime', choices=['historical-e845a6a8', 'current'], default='historical-e845a6a8',
                        help='Saved captures use the fixed historical runtime; select current for newly generated inputs')
    parser.add_argument('--case', choices=list(EXPECTED), help='Replay only one named case')
    args = parser.parse_args()
    expected = {args.case: EXPECTED[args.case]} if args.case else EXPECTED
    instance = args.input / 'instance'
    policy = decode((instance / 'receiver-policy.json').read_bytes())
    if args.runtime == 'historical-e845a6a8':
        api, runtime = historical_api(ROOT)
        assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=runtime)
        policy_raw = (instance / 'receiver-policy.json').read_bytes()
        records = {name: assessor.assess_s3(instance / 'bundles' / name, policy_raw)['native_result']
                   for name in expected}
    else:
        records = {name: assess(instance / 'bundles' / name, policy) for name in expected}
    result = {'all_expected': all(records[name]['assessment'] == expected
                                 and records[name]['retry_authorized'] is False
                                 for name, expected in expected.items()),
              'basis': 'offline replay of stored local captures', 'runtime': args.runtime, 'assessments': records}
    if args.output:
        write(args.output, result)
    print(encode({'runtime': args.runtime, 'all_expected': result['all_expected'],
                  'assessments': {name: r['assessment'] for name, r in records.items()}}).decode())
    return 0 if result['all_expected'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
