"""Isolated entrypoint; its caller pins both this source and the external verifier."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from acceptance_checks import PROFILE, evaluate

VERIFIER_SHA256 = 'ac3ac35d9356cbb5f3371c19a2113ad03c1fd486c247a2ed586bdfdbdd32ae49'


def main():
    source = Path(__file__).parent/'war_verify.py'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != VERIFIER_SHA256:
        raise ValueError('acceptance verifier pin mismatch')
    # Execute the bytes just checked, without a second file read or cached bytecode.
    spec = importlib.util.spec_from_loader('selected_war', loader=None)
    war = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(source), 'exec'), war.__dict__)
    request = json.loads(Path(sys.argv[1]).read_bytes())
    if request['profile'] != PROFILE or len(request['items']) > 16 or len(request['tsa_roots_base64']) > 8:
        raise ValueError('unsupported acceptance job')
    roots = [base64.b64decode(s, validate=True) for s in request['tsa_roots_base64']]
    results = {}
    for item in request['items']:
        if item['id'] in results:
            raise ValueError('duplicate requirement in acceptance job')
        result = evaluate(base64.b64decode(item['raw_base64'], validate=True), item['expected'], roots, war)
        results[item['id']] = dict(result, expected=item['expected'])
    failed = any('evaluator_failed' in r.get('reason_codes', []) for r in results.values())
    print(json.dumps({'profile': PROFILE, 'state': 'evaluator_error' if failed else 'evaluated', 'results': results},
                     ensure_ascii=True, allow_nan=False, sort_keys=True))


if __name__ == '__main__':
    main()
