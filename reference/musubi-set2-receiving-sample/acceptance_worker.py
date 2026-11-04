"""Isolated entrypoint; its caller pins both this source and the external verifier."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from acceptance_checks import PROFILE, WAR_SOURCES, evaluate


def main():
    request = json.loads(Path(sys.argv[1]).read_bytes())
    selected_hash = request.get('verifier_sha256')
    if type(selected_hash) is not str or selected_hash not in WAR_SOURCES:
        raise ValueError('unsupported acceptance verifier source')
    source = Path(__file__).parent/'war_verify.py'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != selected_hash:
        raise ValueError('acceptance verifier pin mismatch')
    # Execute the bytes just checked, without a second file read or cached bytecode.
    spec = importlib.util.spec_from_loader('selected_war', loader=None)
    war = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(source), 'exec'), war.__dict__)
    if request['profile'] != PROFILE or len(request['items']) > 16 or len(request['tsa_roots_base64']) > 8:
        raise ValueError('unsupported acceptance job')
    roots = [base64.b64decode(s, validate=True) for s in request['tsa_roots_base64']]
    results = {}
    for item in request['items']:
        if item['id'] in results:
            raise ValueError('duplicate requirement in acceptance job')
        result = evaluate(base64.b64decode(item['raw_base64'], validate=True), item['expected'], roots, war,
                          verifier_sha256=selected_hash)
        results[item['id']] = dict(result, expected=item['expected'])
    failed = any('evaluator_failed' in r.get('reason_codes', []) for r in results.values())
    print(json.dumps({'profile': PROFILE, 'state': 'evaluator_error' if failed else 'evaluated', 'results': results},
                     ensure_ascii=True, allow_nan=False, sort_keys=True))


if __name__ == '__main__':
    main()
